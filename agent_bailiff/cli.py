from __future__ import annotations

import argparse
import asyncio
import hashlib
import json
import logging
import os
import signal
import sys
import threading
import time
import urllib.parse
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import BinaryIO

from agent_warrant.ledger import LedgerError
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from agent_bailiff.adapters.agentgateway.__main__ import main as check_config_main
from agent_bailiff.adapters.agentgateway.server import ProcessorLocked
from agent_bailiff.client import BailiffClient, GatewayError
from agent_bailiff.control.control import LEVELS, ControlRefused, ControlUnrecorded, Outcome
from agent_bailiff.custodian.backend import BackendError
from agent_bailiff.custodian.files import OwnedFileError
from agent_bailiff.docket.archiver import ArchiveMismatch, ArchiverLocked, DocketArchiver
from agent_bailiff.docket.client import DocketError
from agent_bailiff.docket.grants import INVALID_GRANT, GrantReport, grant_header, grant_json_row, grant_table_row
from agent_bailiff.docket.report import (
    RecordFilter,
    SeedCheck,
    SnapshotCheck,
    json_row,
    pinned_writers,
    printable,
    read_docket_snapshot,
    table_header,
    table_row,
    verify_records,
)
from agent_bailiff.docket.roles import WriterRoles
from agent_bailiff.docket.segments import SegmentMismatch, SegmentRemoved
from agent_bailiff.docket.sink import DocketCorrupt, DocketLocked, VerifiedLine, build_kid_index
from agent_bailiff.docket.tasks import (
    CONTROL_HOP,
    CUSTODIAN_HOP,
    DECIDE_HOP,
    TaskList,
    task_header,
    task_json_chunks,
    task_table_row,
)
from agent_bailiff.effector.catalog import OperationCatalog
from agent_bailiff.effector.drift import RbacDrift
from agent_bailiff.effector.platform import PLATFORMS
from agent_bailiff.effector.rbac import EffectorIdentity, generate_manifests, parse_tenants, render
from agent_bailiff.keys import PublicKeyRecord, load_signing_key
from agent_bailiff.proxy.agent_key import AgentKeyError, generate_agent_key
from agent_bailiff.proxy.authority import SharedAuthority, check_two_user
from agent_bailiff.proxy.server import StdioProxy, Stop, load_routes, read_routes
from agent_bailiff.proxy.task_state import NoTask, TaskState, TaskUnavailable
from agent_bailiff.route_generation import MAX_TOOLS_BYTES, generate_routes, write_new
from agent_bailiff.routes import ToolRoutes
from agent_bailiff.service import run
from agent_bailiff.service.init import (
    DEFAULT_CATALOG,
    InitError,
    init_control,
    init_custodian,
    init_decide,
    init_docket,
    init_effector,
    read_pin,
)
from agent_bailiff.service.settings import (
    DocketClientSettings,
    DocketSettings,
    load_control,
    load_custodian,
    load_decide,
    load_docket,
    load_effector,
    load_issuers,
)
from agent_bailiff.signing import MAX_TOKEN_CHARS
from agent_bailiff.strict_json import parse_strict_json
from agent_bailiff.task.issue import (
    DEFAULT_PRINCIPAL,
    DEFAULT_TENANT,
    DEFAULT_TTL_SECONDS,
    TaskIssueError,
    TaskRequest,
    issue_task,
    write_task_file,
)

PROG = "agent-bailiff"
EXIT_REFUSED = 1
EXIT_UNVERIFIED = 2
EXIT_UNRECORDED = 3
EXIT_UNCOUNTED = 3
TASK_ROLE_FLAGS = {DECIDE_HOP: "--decide-pin", CUSTODIAN_HOP: "--custodian-pin", CONTROL_HOP: "--control-pin"}
MAX_SECRET_BYTES = 65536
TORN_TAIL_HINT = "an append may still be in progress, so run again; if it stays, see Torn tail repair in docs/DOCKET.md"
LOG_FORMAT = "%(asctime)sZ %(levelname)s %(name)s: %(message)s"
STARTUP_ERRORS = (
    OSError,
    ValueError,
    OwnedFileError,
    LedgerError,
    BackendError,
    DocketError,
    DocketLocked,
    DocketCorrupt,
    ProcessorLocked,
    RbacDrift,
)


def main(argv: Sequence[str] | None = None) -> int:
    arguments = list(sys.argv[1:] if argv is None else argv)
    if arguments[:1] == ["check-config"]:
        return check_config_main(arguments)
    args = _parser().parse_args(arguments)
    _configure_logging()
    result: int = args.handler(args)
    return result


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog=PROG)
    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser(
        "check-config",
        help="refuse an agentgateway config the processors cannot enforce (see check-config --help)",
        add_help=False,
    )
    _add_init(commands)
    for name, handler in (
        ("decide", _run_decide),
        ("custodian", _run_custodian),
        ("docket", _run_docket),
        ("effector", _run_effector),
    ):
        component = commands.add_parser(name, help=f"the {name} service").add_subparsers(dest="action", required=True)
        serve = component.add_parser("run", help=f"run the {name} service until SIGTERM or SIGINT")
        serve.add_argument("--config", type=Path, required=True)
        serve.set_defaults(handler=handler)
        if name == "effector":
            manifests = component.add_parser(
                "manifests", help="print the RBAC and admission objects for the catalog as a kubectl List"
            )
            manifests.add_argument("--catalog", type=Path, default=DEFAULT_CATALOG)
            manifests.add_argument("--namespace", required=True, help="the effector's own namespace")
            manifests.add_argument("--service-account", required=True)
            manifests.add_argument("--applier", required=True, help="the user that applies generated RBAC (GitOps)")
            manifests.add_argument("--webhook-namespace", required=True, help="the release webhook's namespace")
            manifests.add_argument(
                "--tenant", action="append", required=True, help="tenant=namespace[,namespace...]; repeat"
            )
            manifests.set_defaults(handler=_effector_manifests)
            digest = component.add_parser("digest", help="print the catalog digest for custodian effector bindings")
            digest.add_argument("--catalog", type=Path, default=DEFAULT_CATALOG)
            digest.set_defaults(handler=_effector_digest)
        if name == "docket":
            verify = component.add_parser(
                "verify", help="verify every record against writer pins and print the selected ones"
            )
            verify.add_argument("--docket", type=Path, required=True, help="the docket file; needs read access only")
            verify.add_argument(
                "--pin", type=Path, action="append", required=True, help="writer public key record; repeat"
            )
            verify.add_argument("--trace", help="print only records of this trace id")
            verify.add_argument("--task", help="print only records of this task root, and its grant")
            verify.add_argument("--since", type=int, help="print only records at or after this Unix time (UTC)")
            verify.add_argument("--json", action="store_true", help="print one JSON object per record")
            verify.add_argument("--snapshot", type=Path, help="also cross-check this heads snapshot against the docket")
            verify.add_argument(
                "--archive", type=Path, help="verify removed segments from this archive, from the first record"
            )
            verify.add_argument(
                "--receipts", type=Path, help="also cross-check the manifest seeds against this receipt directory"
            )
            verify.set_defaults(handler=_verify_docket)
            tasks = component.add_parser(
                "tasks", help="verify every record and print one row per task; --json rows carry a record to revoke"
            )
            tasks.add_argument("--docket", type=Path, required=True, help="the docket file; needs read access only")
            tasks.add_argument(
                "--pin",
                type=Path,
                action="append",
                default=[],
                help="public key record of a writer that is verified but feeds no row; repeat",
            )
            tasks.add_argument(
                "--decide-pin",
                type=Path,
                action="append",
                required=True,
                help="decide's public key record; only its records count allows and set PRINCIPAL; repeat",
            )
            tasks.add_argument(
                "--custodian-pin",
                type=Path,
                action="append",
                required=True,
                help="custodian's public key record; only its records count releases; repeat",
            )
            tasks.add_argument(
                "--control-pin",
                type=Path,
                action="append",
                required=True,
                help="control's public key record; only its revocations set STATE; repeat",
            )
            tasks.add_argument(
                "--archive", type=Path, help="read removed segments from this archive, so older tasks are listed"
            )
            tasks.add_argument("--json", action="store_true", help="print one JSON object per task")
            tasks.set_defaults(handler=_list_tasks)
            grants = component.add_parser(
                "grants",
                help="verify every record and print granted versus used per task root; advisory, exit 1 on an "
                "invalid grant, 2 when the docket fails verification",
            )
            grants.add_argument("--docket", type=Path, required=True, help="the docket file; needs read access only")
            grants.add_argument(
                "--pin", type=Path, action="append", required=True, help="writer public key record; repeat"
            )
            grants.add_argument(
                "--issuers",
                type=Path,
                required=True,
                help="0600 JSON file holding the issuers section of decide's config; checks each grant's task root",
            )
            grants.add_argument(
                "--archive", type=Path, help="read removed segments from this archive, so older grants are listed"
            )
            grants.add_argument("--json", action="store_true", help="print one JSON object per task root")
            grants.set_defaults(handler=_report_grants)
            export = component.add_parser(
                "export", help="export verified records as OTLP spans, resuming from a checkpoint (needs [otel])"
            )
            export.add_argument("--docket", type=Path, required=True, help="the docket file; needs read access only")
            export.add_argument(
                "--pin", type=Path, action="append", required=True, help="writer public key record; repeat"
            )
            export.add_argument(
                "--checkpoint", type=Path, required=True, help="checkpoint file in the exporter's own 0700 directory"
            )
            export.add_argument(
                "--otlp", required=True, help="OTLP/HTTP traces endpoint, e.g. http://jaeger:4318/v1/traces"
            )
            export.add_argument("--timeout", type=float, default=10.0, help="seconds per export, retries included")
            export.add_argument("--batch-size", type=int, default=256)
            export.add_argument("--max-failures", type=int, default=5, help="failed exports of one batch before exit")
            export.add_argument("--poll-interval", type=float, default=1.0, help="seconds between reads at the end")
            export.add_argument("--once", action="store_true", help="export to the current end, then exit")
            export.add_argument(
                "--skip-line",
                type=int,
                help="export the next line, which must be this one, as a skipped marker span instead of its record",
            )
            export.add_argument(
                "--archive", type=Path, help="read removed segments from this archive; a new checkpoint starts at 1"
            )
            export.set_defaults(handler=_export_docket)
            archive = component.add_parser(
                "archive", help="copy sealed segments to separate storage and write a receipt for each"
            )
            archive.add_argument("--docket", type=Path, required=True, help="the docket file; needs read access only")
            archive.add_argument(
                "--pin", type=Path, action="append", required=True, help="writer public key record; repeat"
            )
            archive.add_argument(
                "--archive", type=Path, required=True, help="archive directory on another device, owned by this uid"
            )
            archive.add_argument(
                "--receipts", type=Path, required=True, help="receipt directory, this uid and reader_group, 0750"
            )
            archive.add_argument(
                "--checkpoint", type=Path, required=True, help="checkpoint file in the archiver's own 0700 directory"
            )
            archive.add_argument("--poll-interval", type=float, default=10.0, help="seconds between manifest reads")
            archive.add_argument(
                "--refresh-interval",
                type=float,
                default=900.0,
                help="seconds, give or take 10%%, between rechecks of archived copies; keep under max_receipt_age",
            )
            archive.add_argument(
                "--once", action="store_true", help="archive every sealed segment and recheck receipts, then exit"
            )
            archive.set_defaults(handler=_archive_docket)
            for reader in (verify, tasks, grants, export, archive):
                reader.add_argument(
                    "--grant-pin",
                    type=Path,
                    action="append",
                    default=[],
                    help="grant writer public key record; its writer may record only grants; repeat",
                )
        if name == "custodian":
            put = component.add_parser("put-credential", help="store a credential read from stdin")
            put.add_argument("--config", type=Path, required=True)
            put.add_argument("--tenant", required=True)
            put.add_argument("--credential-id", required=True)
            put.add_argument("--target", required=True)
            put.set_defaults(handler=_put_credential)
    control = commands.add_parser("control", help="revoke or suspend from a docket record; run as decide's uid")
    actions = control.add_subparsers(dest="action", required=True)
    revoke = actions.add_parser("revoke", help="revoke the record's handle at one level")
    revoke.add_argument("--level", required=True, choices=LEVELS)
    suspend = actions.add_parser("suspend", help="suspend decide; joins the record's trace")
    resume = actions.add_parser("resume", help="lift a suspension")
    for action in (revoke, suspend, resume):
        action.add_argument("--config", type=Path, required=True)
        action.add_argument("--actor", required=True, help="operator name recorded in the docket entry")
        action.set_defaults(handler=_control)
    for action in (revoke, suspend):
        action.add_argument("--record", required=True, help="file holding one signed docket line, or - for stdin")
    _add_proxy(commands)
    _add_routes(commands)
    _add_task(commands)
    return parser


def _add_task(commands: argparse._SubParsersAction[argparse.ArgumentParser]) -> None:
    task = commands.add_parser("task", help="issue task roots; run as the issuer's uid, never the agent's")
    actions = task.add_subparsers(dest="action", required=True)
    issue = actions.add_parser("issue", help="issue a task root to an agent key and write task.json")
    issue.add_argument("--issuer-key", type=Path, required=True, help="the issuer's 0600 signing key")
    issue.add_argument("--issuer", required=True, help="the issuer name decide trusts")
    issue.add_argument("--decider-id", required=True, help="decide's name")
    issue.add_argument("--tenant", default=DEFAULT_TENANT)
    issue.add_argument("--principal", default=DEFAULT_PRINCIPAL)
    issue.add_argument("--purpose", required=True)
    issue.add_argument(
        "--scope",
        required=True,
        help='JSON: {"permissions": [{"tools": [...], "resources": [...], "max_cost_per_call": n}, ...]}',
    )
    issue.add_argument("--budget", type=int, required=True)
    issue.add_argument("--ttl", type=int, default=DEFAULT_TTL_SECONDS, help="seconds, at most 86400")
    issue.add_argument("--max-depth", type=int, default=0, help="delegation depth below the agent, at most 2")
    issue.add_argument(
        "--subject",
        required=True,
        help="the agent's public key from proxy keygen; pass as --subject=KEY, it may start with -",
    )
    issue.add_argument(
        "--out-dir", type=Path, required=True, help="task directory owned by this uid, not group or other writable"
    )
    issue.add_argument("--docket-socket", type=Path, required=True, help="the docket sink's socket")
    issue.add_argument("--docket-uid", type=int, required=True, help="the docket sink's uid")
    issue.add_argument(
        "--docket-writer", required=True, help="this issuer's docket writer, pinned in the docket as a grant writer"
    )
    issue.add_argument(
        "--docket-key", type=Path, required=True, help="the docket writer's 0600 signing key, not the issuer key"
    )
    issue.add_argument(
        "--docket-state-dir", type=Path, required=True, help="the docket writer's own 0700 state directory"
    )
    issue.set_defaults(handler=_task_issue)


def _add_proxy(commands: argparse._SubParsersAction[argparse.ArgumentParser]) -> None:
    proxy = commands.add_parser("proxy", help="the agent side: a stdio MCP server; run as the agent's uid")
    actions = proxy.add_subparsers(dest="action", required=True)
    keygen = actions.add_parser("keygen", help="create a signing key for the next task and print its public key")
    keygen.add_argument("--key-dir", type=Path, required=True, help="the agent's own 0700 key directory")
    keygen.set_defaults(handler=_proxy_keygen)
    tools = actions.add_parser("tools", help="print the gateway's tools/list as JSON, the input to routes generate")
    _add_task_source(tools)
    tools.set_defaults(handler=_proxy_tools)
    serve = actions.add_parser("run", help="serve MCP on stdin and stdout until EOF, SIGINT or SIGTERM")
    _add_task_source(serve)
    serve.add_argument("--routes", type=Path, required=True, help="the route table the gateway enforces")
    serve.add_argument(
        "--allow-shared-user",
        action="store_true",
        help="start although this user can reach the Docker daemon; single-user development only",
    )
    serve.set_defaults(handler=_proxy_run)


def _add_routes(commands: argparse._SubParsersAction[argparse.ArgumentParser]) -> None:
    routes = commands.add_parser("routes", help="draft route tables")
    actions = routes.add_subparsers(dest="action", required=True)
    generate = actions.add_parser(
        "generate", help="draft a route table from proxy tools output; fill each resource before use"
    )
    generate.add_argument("--tools", type=Path, required=True, help="the JSON proxy tools printed")
    generate.add_argument("--service", required=True, help="the gateway service these tools belong to")
    generate.add_argument("--out", type=Path, required=True, help="route table to create; never overwritten")
    generate.set_defaults(handler=_routes_generate)


def _add_task_source(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--task-file", type=Path, required=True, help="task.json written by task issue")
    parser.add_argument("--key-dir", type=Path, required=True, help="the agent's own 0700 key directory")
    parser.add_argument("--gateway-url", required=True, help="the agentgateway MCP URL")


def _add_init(commands: argparse._SubParsersAction[argparse.ArgumentParser]) -> None:
    components = commands.add_parser(
        "init", help="create a component's key and config; run as that component's uid"
    ).add_subparsers(dest="component", required=True)
    decide = components.add_parser("decide")
    decide.add_argument("--custodian", action="append", required=True, help="custodian name; repeat for each")
    decide.add_argument("--ledger", type=Path, required=True, help="ledger file to create")
    decide.add_argument("--ledger-group", type=int, required=True, help="group that may read the ledger")
    custodian = components.add_parser("custodian")
    custodian.add_argument("--decide-pin", type=Path, required=True, help="decide's public key record")
    custodian.add_argument("--ledger", type=Path, required=True)
    custodian.add_argument("--ledger-uid", type=int, required=True, help="decide's uid, the ledger owner")
    custodian.add_argument("--ledger-group", type=int, required=True)
    custodian.add_argument("--response-socket", required=True, help="response check socket the gateway connects to")
    control = components.add_parser("control")
    control.add_argument("--decide-config", type=Path, required=True)
    effector = components.add_parser("effector")
    effector.add_argument("--custodian-pin", type=Path, required=True, help="the custodian's public key record")
    effector.add_argument("--decide-pin", type=Path, required=True, help="decide's public key record")
    effector.add_argument("--ledger", type=Path, required=True, help="decide's ledger (its suspension is read)")
    effector.add_argument("--ledger-uid", type=int, required=True)
    effector.add_argument("--ledger-group", type=int, required=True)
    effector.add_argument("--port", type=int, required=True, help="127.0.0.1 port the gateway reaches")
    effector.add_argument(
        "--platform", choices=PLATFORMS, default="upstream", help="the cluster's platform; upstream is strictest"
    )
    effector.add_argument("--kube-host", required=True)
    effector.add_argument("--kube-port", type=int, required=True)
    effector.add_argument("--kube-ca", type=Path, required=True)
    effector.add_argument("--kube-token-file", type=Path, required=True, help="the effector's own token, 0600")
    effector.add_argument("--kube-audit-token-file", type=Path, required=True, help="the audit identity's token, 0600")
    effector.add_argument("--effector-namespace", required=True)
    effector.add_argument("--service-account", required=True)
    effector.add_argument("--applier", required=True, help="the user that applies generated RBAC (GitOps)")
    effector.add_argument("--webhook-namespace", required=True, help="the release webhook's namespace")
    effector.add_argument("--tenant", action="append", required=True, help="tenant=namespace[,namespace...]")
    docket = components.add_parser("docket")
    docket.add_argument("--socket", type=Path, required=True)
    docket.add_argument("--socket-group", type=int, required=True)
    docket.add_argument(
        "--reader-group", type=int, required=True, help="group that may read the docket (file 0640, dir 0750)"
    )
    docket.add_argument("--receipt-dir", type=Path, required=True, help="the archiver's receipt directory")
    docket.add_argument("--archiver-uid", type=int, required=True, help="the uid that writes archive receipts")
    docket.add_argument("--allowed-uid", type=int, action="append", required=True, help="writer uid; repeat")
    for parser in (control, docket):
        parser.add_argument("--pin", type=Path, action="append", required=True, help="writer public key record")
        parser.add_argument(
            "--grant-pin",
            type=Path,
            action="append",
            default=[],
            help="grant writer public key record; its writer may record only grants; repeat",
        )
    for parser in (decide, custodian, control, docket, effector):
        parser.add_argument("--dir", type=Path, required=True, help="the component's 0700 directory")
        parser.set_defaults(handler=_init)
    for parser in (decide, custodian, control, effector):
        parser.add_argument("--name", required=True, help="component name, also its docket writer and key id prefix")
        parser.add_argument("--docket-socket", required=True)
        parser.add_argument("--docket-uid", type=int, required=True, help="the docket sink's uid")
    for parser in (decide, custodian):
        parser.add_argument("--socket", required=True, help="processor socket the gateway connects to")
        parser.add_argument("--gateway-uid", type=int, required=True)
        parser.add_argument("--gateway-group", type=int, required=True)


def _init(args: argparse.Namespace) -> int:
    try:
        record = _init_component(args)
    except STARTUP_ERRORS + (InitError,) as exc:
        return _refused("init", exc)
    print(f"{PROG} init: wrote {args.dir / 'config.json'}", file=sys.stderr)
    if record is not None:
        print(json.dumps(record.to_document(), sort_keys=True))
    return 0


def _init_component(args: argparse.Namespace) -> PublicKeyRecord | None:
    if args.component == "docket":
        pins = [read_pin(path) for path in args.pin]
        init_docket(
            args.dir,
            socket=args.socket,
            socket_group=args.socket_group,
            reader_group=args.reader_group,
            allowed_uids=args.allowed_uid,
            pins=pins,
            grant_pins=[read_pin(path) for path in args.grant_pin],
            receipt_dir=args.receipt_dir,
            archiver_uid=args.archiver_uid,
        )
        return None
    docket = {"socket": args.docket_socket, "sink_uid": args.docket_uid}
    if args.component == "control":
        return init_control(
            args.dir,
            name=args.name,
            decide_config=args.decide_config,
            pins=[read_pin(path) for path in args.pin],
            grant_pins=[read_pin(path) for path in args.grant_pin],
            docket=docket,
        )
    if args.component == "effector":
        kubernetes = {
            "host": args.kube_host,
            "port": args.kube_port,
            "ca": args.kube_ca,
            "token_file": args.kube_token_file,
            "audit_token_file": args.kube_audit_token_file,
        }
        rbac = {
            "namespace": args.effector_namespace,
            "service_account": args.service_account,
            "applier": args.applier,
            "webhook_namespace": args.webhook_namespace,
            "tenants": parse_tenants(args.tenant),
        }
        return init_effector(
            args.dir,
            name=args.name,
            custodian=read_pin(args.custodian_pin),
            decide=read_pin(args.decide_pin),
            ledger=args.ledger,
            ledger_uid=args.ledger_uid,
            ledger_group=args.ledger_group,
            port=args.port,
            platform=args.platform,
            kubernetes=kubernetes,
            rbac=rbac,
            docket=docket,
        )
    gateway = {"uid": args.gateway_uid, "socket": args.socket, "socket_group": args.gateway_group}
    if args.component == "decide":
        return init_decide(
            args.dir,
            name=args.name,
            custodians=args.custodian,
            ledger=args.ledger,
            ledger_group=args.ledger_group,
            docket=docket,
            gateway=gateway,
        )
    return init_custodian(
        args.dir,
        name=args.name,
        decide=read_pin(args.decide_pin),
        ledger=args.ledger,
        ledger_uid=args.ledger_uid,
        ledger_group=args.ledger_group,
        docket=docket,
        gateway=gateway,
        response_socket=args.response_socket,
    )


def _run_decide(args: argparse.Namespace) -> int:
    stop = _stop_on_signals()
    try:
        service = run.start_decide(load_decide(args.config))
    except STARTUP_ERRORS as exc:
        return _refused("decide", exc)
    try:
        service.serve(stop)
    finally:
        service.close()
    return 0


def _run_custodian(args: argparse.Namespace) -> int:
    stop = _stop_on_signals()
    try:
        service = run.start_custodian(load_custodian(args.config))
    except STARTUP_ERRORS as exc:
        return _refused("custodian", exc)
    try:
        stop.wait()
    finally:
        service.close()
    return 0


def _run_effector(args: argparse.Namespace) -> int:
    stop = _stop_on_signals()
    try:
        service = run.start_effector(load_effector(args.config))
    except STARTUP_ERRORS as exc:
        return _refused("effector", exc)
    try:
        stop.wait()
    finally:
        service.close()
    return 0


def _effector_manifests(args: argparse.Namespace) -> int:
    try:
        tenants = parse_tenants(args.tenant)
        identity = EffectorIdentity(args.namespace, args.service_account, args.applier, args.webhook_namespace)
        output = render(generate_manifests(OperationCatalog.load(args.catalog), identity, tenants))
    except STARTUP_ERRORS as exc:
        return _refused("effector manifests", exc)
    sys.stdout.write(output)
    return 0


def _effector_digest(args: argparse.Namespace) -> int:
    try:
        catalog = OperationCatalog.load(args.catalog)
    except STARTUP_ERRORS as exc:
        return _refused("effector digest", exc)
    print(catalog.digest)
    return 0


def _run_docket(args: argparse.Namespace) -> int:
    try:
        settings = load_docket(args.config)
    except STARTUP_ERRORS as exc:
        return _refused("docket", exc)
    try:
        asyncio.run(_serve_docket_until_signal(settings))
    except STARTUP_ERRORS as exc:
        return _refused("docket", exc)
    return 0


def _list_tasks(args: argparse.Namespace) -> int:
    try:
        writers, grant_writers, roles = _role_pins(args, TASK_ROLE_FLAGS)
        tasks = TaskList(roles)
        report = verify_records(
            args.docket, writers, RecordFilter(), tasks.add, archive=args.archive, grant_writers=grant_writers
        )
    except STARTUP_ERRORS + (InitError, ArchiveMismatch, SegmentMismatch, SegmentRemoved) as exc:
        return _refused("docket tasks", exc)
    if not report.ok:
        where = "the docket" if report.line is None else f"line {report.line}"
        print(
            f"{PROG} docket tasks: {where} fails verification: {report.reason} {printable(report.detail)}; "
            "no tasks printed",
            file=sys.stderr,
        )
        return EXIT_REFUSED
    rows = tasks.rows()
    print(f"{PROG} docket tasks: {report.entries} records verified, {len(rows)} tasks", file=sys.stderr)
    if tasks.undecodable_grants:
        print(
            f"{PROG} docket tasks: {tasks.undecodable_grants} grants hold a task root that does not decode; "
            "their tasks are not listed",
            file=sys.stderr,
        )
    _warn_role_mismatches("docket tasks", tasks.role_mismatches)
    sys.stderr.flush()
    if not args.json:
        print(task_header())
    for row in rows:
        if args.json:
            sys.stdout.writelines(task_json_chunks(row))
            sys.stdout.write("\n")
        else:
            print(task_table_row(row))
    return EXIT_UNCOUNTED if tasks.role_mismatches else 0


def _report_grants(args: argparse.Namespace) -> int:
    try:
        issuers = load_issuers(args.issuers)
        writers, grant_writers = _docket_pins([read_pin(path) for path in args.pin], args.grant_pin)
        grants = GrantReport(issuers.resolver, issuers.trust_policy)
        report = verify_records(
            args.docket, writers, RecordFilter(), grants.add, archive=args.archive, grant_writers=grant_writers
        )
    except STARTUP_ERRORS + (InitError, ArchiveMismatch, SegmentMismatch, SegmentRemoved) as exc:
        print(f"{PROG} docket grants refused: {exc}", file=sys.stderr)
        return EXIT_UNVERIFIED
    if not report.ok:
        where = "the docket" if report.line is None else f"line {report.line}"
        print(
            f"{PROG} docket grants: {where} fails verification: {report.reason} {printable(report.detail)}; "
            "no grants printed",
            file=sys.stderr,
        )
        return EXIT_UNVERIFIED
    if not args.json:
        print(grant_header())
    roots = invalid = 0
    for row in grants.rows():
        print(grant_json_row(row) if args.json else grant_table_row(row))
        roots += 1
        invalid += row.status == INVALID_GRANT
    print(
        f"{PROG} docket grants: {report.entries} records verified, {roots} roots, {invalid} invalid grants",
        file=sys.stderr,
    )
    return EXIT_REFUSED if invalid else 0


def _verify_docket(args: argparse.Namespace) -> int:
    selected = RecordFilter(trace=args.trace, task=args.task, since=args.since)
    shown = 0

    def emit(verified: VerifiedLine) -> None:
        nonlocal shown
        shown += 1
        print(json_row(verified) if args.json else table_row(verified))

    try:
        writers, grant_writers = _docket_pins([read_pin(path) for path in args.pin], args.grant_pin)
        check = None if args.snapshot is None else SnapshotCheck(read_docket_snapshot(args.snapshot, args.docket))
        if not args.json:
            print(table_header())
        seeds = None if args.receipts is None else SeedCheck(args.receipts)
        report = verify_records(
            args.docket, writers, selected, emit, check, args.archive, seeds, grant_writers=grant_writers
        )
    except STARTUP_ERRORS + (InitError, ArchiveMismatch, SegmentMismatch, SegmentRemoved) as exc:
        return _refused("docket verify", exc)
    if not report.ok:
        where = "the docket" if report.line is None else f"line {report.line}"
        print(
            f"{PROG} docket verify: {where} fails verification: {report.reason} {printable(report.detail)}; "
            f"{report.entries} records before it verified, {shown} printed",
            file=sys.stderr,
        )
        if report.reason == "torn_tail":
            print(f"{PROG} docket verify: {TORN_TAIL_HINT}", file=sys.stderr)
        return EXIT_REFUSED
    print(f"{PROG} docket verify: {report.entries} records verified, {shown} printed", file=sys.stderr)
    if seeds is not None and not _seeds_match(args.receipts, seeds):
        return EXIT_REFUSED
    if check is None:
        return 0
    differences = check.differences()
    if differences:
        print(
            f"{PROG} docket verify: snapshot {args.snapshot} does not match the docket: {', '.join(differences)}",
            file=sys.stderr,
        )
        return EXIT_REFUSED
    print(
        f"{PROG} docket verify: snapshot at offset {check.snapshot.offset} matches the docket, "
        f"{check.records_after(report.entries)} records after it",
        file=sys.stderr,
    )
    return 0


def _seeds_match(receipts: Path, seeds: SeedCheck) -> bool:
    if seeds.differences:
        print(
            f"{PROG} docket verify: receipts {receipts} do not match the manifest: {'; '.join(seeds.differences)}",
            file=sys.stderr,
        )
        return False
    base = "" if seeds.base is None else f" and the base matches removed segment {seeds.base}"
    print(
        f"{PROG} docket verify: {seeds.checked} retained segments match their receipts{base}",
        file=sys.stderr,
    )
    return True


def _export_docket(args: argparse.Namespace) -> int:
    try:
        from opentelemetry.sdk.trace.export import SpanExporter

        from agent_bailiff.docket.follower import CheckpointMismatch, FollowerLocked
        from agent_bailiff.docket.otlp import DocketExporter, ExportFailed, OtlpHttpExporter
    except ImportError:
        return _refused("docket export", ImportError("needs the otel extra: pip install 'agent-bailiff[otel]'"))
    stop = _stop_on_signals()
    try:
        endpoint = _otlp_endpoint(args.otlp)
        index = build_kid_index(*_docket_pins([read_pin(path) for path in args.pin], args.grant_pin))
        span_exporter: SpanExporter = OtlpHttpExporter(endpoint, timeout=args.timeout)
    except STARTUP_ERRORS + (InitError,) as exc:
        return _refused("docket export", exc)
    try:
        exporter = DocketExporter(
            args.docket,
            index,
            args.checkpoint,
            span_exporter,
            batch_size=args.batch_size,
            max_failures=args.max_failures,
            poll_interval=args.poll_interval,
            skip_line=args.skip_line,
            archive=args.archive,
        )
        exported = exporter.run(stop, follow=not args.once)
    except STARTUP_ERRORS + (
        ArchiveMismatch,
        CheckpointMismatch,
        ExportFailed,
        FollowerLocked,
        SegmentMismatch,
        SegmentRemoved,
    ) as exc:
        return _refused("docket export", exc)
    finally:
        span_exporter.shutdown()
    print(f"{PROG} docket export: {exported} records exported", file=sys.stderr)
    return 0


def _archive_docket(args: argparse.Namespace) -> int:
    stop = _stop_on_signals()
    try:
        index = build_kid_index(*_docket_pins([read_pin(path) for path in args.pin], args.grant_pin))
        archiver = DocketArchiver(
            args.docket,
            index,
            args.archive,
            args.receipts,
            args.checkpoint,
            poll_interval=args.poll_interval,
            refresh_interval=args.refresh_interval,
        )
        archived = archiver.run(stop, follow=not args.once)
    except STARTUP_ERRORS + (InitError, ArchiveMismatch, ArchiverLocked, SegmentMismatch) as exc:
        return _refused("docket archive", exc)
    print(f"{PROG} docket archive: {archived} segments archived", file=sys.stderr)
    return 0


def _docket_pins(
    pins: Sequence[PublicKeyRecord], grant_pin_paths: Sequence[Path]
) -> tuple[dict[str, dict[str, Ed25519PublicKey]], frozenset[str]]:
    grants = [read_pin(path) for path in grant_pin_paths]
    grant_writers = frozenset(pin.component for pin in grants)
    both = sorted({pin.component for pin in pins} & grant_writers)
    if both:
        raise InitError(f"writers pinned both as entry and grant writers: {', '.join(both)}")
    return pinned_writers([*pins, *grants]), grant_writers


def _role_pins(
    args: argparse.Namespace, role_flags: Mapping[str, str]
) -> tuple[dict[str, dict[str, Ed25519PublicKey]], frozenset[str], WriterRoles]:
    flags = ["--pin", *role_flags.values(), "--grant-pin"]
    pins = {flag: [read_pin(path) for path in getattr(args, flag[2:].replace("-", "_"))] for flag in flags}
    owners: dict[str, str] = {}
    for flag in flags:
        for pin in pins[flag]:
            owner = owners.setdefault(pin.component, flag)
            if owner != flag:
                raise InitError(f"writer {pin.component} is pinned as both {owner} and {flag}")
    names: dict[bytes, str] = {}
    for pin in (pin for flag in flags for pin in pins[flag]):
        name = names.setdefault(pin.public_key.public_bytes_raw(), pin.component)
        if name != pin.component:
            first, second = sorted((name, pin.component))
            raise InitError(f"writers {first} and {second} are pinned with the same public key")
    roles = WriterRoles({hop: frozenset(pin.component for pin in pins[flag]) for hop, flag in role_flags.items()})
    grant_writers = frozenset(pin.component for pin in pins["--grant-pin"])
    return pinned_writers(pin for flag in flags for pin in pins[flag]), grant_writers, roles


def _warn_role_mismatches(command: str, mismatches: int) -> None:
    if mismatches:
        print(
            f"{PROG} {command}: {mismatches} records claim a hop their writer is not pinned for; they are not counted",
            file=sys.stderr,
        )


def _otlp_endpoint(value: str) -> str:
    parsed = urllib.parse.urlsplit(value)
    if parsed.scheme not in ("http", "https") or not parsed.hostname or parsed.username or parsed.password:
        raise ValueError("--otlp must be an http or https URL with a host and no user info")
    return value


async def _serve_docket_until_signal(settings: DocketSettings) -> None:
    stop = asyncio.Event()
    loop = asyncio.get_running_loop()
    for number in (signal.SIGTERM, signal.SIGINT):
        loop.add_signal_handler(number, stop.set)
    await run.serve_docket(settings, stop)


def _proxy_keygen(args: argparse.Namespace) -> int:
    try:
        subject = generate_agent_key(args.key_dir)
    except AgentKeyError as exc:
        return _refused("proxy keygen", exc)
    print(subject)
    return 0


def _proxy_tools(args: argparse.Namespace) -> int:
    try:
        state = TaskState.load(args.task_file, args.key_dir)
        client = BailiffClient(args.gateway_url, state.holder, ToolRoutes(()))
        try:
            tools = client.list_tools()
        finally:
            client.close()
    except (NoTask, TaskUnavailable, GatewayError, ValueError) as exc:
        return _refused("proxy tools", exc)
    print(json.dumps({"tools": tools}, indent=2, sort_keys=True))
    return 0


def _proxy_run(args: argparse.Namespace) -> int:
    try:
        warning = check_two_user(os.environ, allow_shared_user=args.allow_shared_user)
        raw = read_routes(args.routes)
        proxy = StdioProxy(args.task_file, args.key_dir, args.gateway_url, load_routes(raw))
    except (SharedAuthority, OSError, ValueError) as exc:
        return _refused("proxy run", exc)
    if warning:
        print(f"{PROG} proxy run warning: {warning}", file=sys.stderr)
    _stop_proxy_on_signals(proxy)
    logging.getLogger(__name__).info("proxy routes sha256 %s", hashlib.sha256(raw).hexdigest())
    proxy.run(sys.stdin.buffer, sys.stdout.buffer)
    return 0


def _stop_proxy_on_signals(proxy: StdioProxy) -> None:
    def stop(_signum: int, _frame: object) -> None:
        if proxy.busy:
            proxy.stop_requested = True
            return
        raise Stop

    for number in (signal.SIGTERM, signal.SIGINT):
        signal.signal(number, stop)


def _routes_generate(args: argparse.Namespace) -> int:
    try:
        with args.tools.open("rb") as source:
            raw = source.read(MAX_TOOLS_BYTES + 1)
        if len(raw) > MAX_TOOLS_BYTES:
            raise ValueError(f"the tools document is larger than {MAX_TOOLS_BYTES} bytes")
        document, rejected = generate_routes(parse_strict_json(raw), args.service)
        write_new(args.out, json.dumps(document, indent=2).encode() + b"\n")
    except (OSError, ValueError) as exc:
        return _refused("routes generate", exc)
    for item in rejected:
        print(f"{PROG} routes generate: rejected {item.name!r}: {item.reason}", file=sys.stderr)
    print(
        f"{PROG} routes generate: wrote {len(document['routes'])} route(s) to {args.out}; fill each resource",
        file=sys.stderr,
    )
    return EXIT_REFUSED if rejected else 0


def _task_issue(args: argparse.Namespace) -> int:
    now = int(time.time())
    try:
        request = TaskRequest(
            purpose=args.purpose,
            scope=parse_strict_json(args.scope),
            budget=args.budget,
            subject=args.subject,
            tenant=args.tenant,
            principal=args.principal,
            ttl=args.ttl,
            max_depth=args.max_depth,
        )
        issuer_key = load_signing_key(args.issuer_key)
        docket_key = load_signing_key(args.docket_key)
        if docket_key.public_key() == issuer_key.public_key():
            raise ValueError("--docket-key must be the docket writer's own key, not the issuer key")
        task = issue_task(issuer_key, args.issuer, args.decider_id, request, now)
        settings = DocketClientSettings(args.docket_socket, args.docket_uid, args.docket_state_dir)
        docket = run.docket_client(settings, args.docket_writer, docket_key)
        try:
            issued = write_task_file(args.out_dir, task, issuer_key.public_key(), docket, now)
        finally:
            docket.close()
    except STARTUP_ERRORS + (TaskIssueError,) as exc:
        return _refused("task issue", exc)
    print(
        f"{PROG} task issue: wrote {issued.path}, expires at {issued.task.root.expires_at}, grant_id {issued.grant_id}",
        file=sys.stderr,
    )
    print(issued.task.root.task_id)
    return 0


def _put_credential(args: argparse.Namespace) -> int:
    try:
        secret = _read_secret()
        run.put_credential(load_custodian(args.config), args.tenant, args.credential_id, args.target, secret)
    except STARTUP_ERRORS as exc:
        return _refused("put-credential", exc)
    print("stored")
    return 0


def _control(args: argparse.Namespace) -> int:
    try:
        settings = load_control(args.config)
        record = _read_record(args.record) if args.action != "resume" else None
        session = run.open_control(settings, load_decide(settings.decide_config))
    except STARTUP_ERRORS as exc:
        return _refused("control", exc)
    now = int(time.time())
    try:
        if args.action == "revoke":
            outcome = session.control.revoke(record, args.level, args.actor, now)
        elif args.action == "suspend":
            outcome = session.control.suspend(record, args.actor, now)
        else:
            outcome = session.control.resume(args.actor, now)
    except ControlRefused as refusal:
        return _refused("control", refusal)
    except ControlUnrecorded as unrecorded:
        _print_outcome(unrecorded.outcome)
        print(f"{PROG} control: {unrecorded}", file=sys.stderr)
        return EXIT_UNRECORDED
    finally:
        session.close()
    _print_outcome(outcome)
    return 0


def _read_secret() -> bytes:
    secret = _read_limited(sys.stdin.buffer, MAX_SECRET_BYTES, "secret")
    for ending in (b"\r\n", b"\n"):
        if secret.endswith(ending):
            secret = secret[: -len(ending)]
            break
    if not secret:
        raise ValueError("the secret on stdin is empty")
    return secret


def _read_record(source: str) -> str:
    if source == "-":
        raw = _read_limited(sys.stdin.buffer, MAX_TOKEN_CHARS + 2, "record")
    else:
        with open(source, "rb") as stream:
            raw = _read_limited(stream, MAX_TOKEN_CHARS + 2, "record")
    text = raw.decode("ascii")
    return text[:-1] if text.endswith("\n") else text


def _read_limited(stream: BinaryIO, limit: int, label: str) -> bytes:
    data = stream.read(limit + 1)
    if len(data) > limit:
        raise ValueError(f"the {label} is larger than {limit} bytes")
    return data


def _print_outcome(outcome: Outcome) -> None:
    document = {
        "action": outcome.action,
        "reason": outcome.reason,
        "trace_id": outcome.trace_id,
        "entry_id": outcome.entry_id,
        "handles": dict(outcome.handles),
    }
    print(json.dumps(document, sort_keys=True))


def _stop_on_signals() -> threading.Event:
    stop = threading.Event()
    for number in (signal.SIGTERM, signal.SIGINT):
        signal.signal(number, lambda _signum, _frame: stop.set())
    return stop


def _refused(command: str, exc: BaseException) -> int:
    print(f"{PROG} {command} refused: {exc}", file=sys.stderr)
    return EXIT_REFUSED


def _configure_logging() -> None:
    logging.Formatter.converter = time.gmtime
    logging.basicConfig(stream=sys.stderr, level=logging.INFO, format=LOG_FORMAT)


if __name__ == "__main__":
    sys.exit(main())
