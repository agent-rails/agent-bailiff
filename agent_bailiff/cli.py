from __future__ import annotations

import argparse
import asyncio
import json
import logging
import signal
import sys
import threading
import time
import urllib.parse
from collections.abc import Sequence
from pathlib import Path
from typing import BinaryIO

from agent_warrant.ledger import LedgerError

from agent_bailiff.adapters.agentgateway.__main__ import main as check_config_main
from agent_bailiff.adapters.agentgateway.server import ProcessorLocked
from agent_bailiff.control.control import LEVELS, ControlRefused, ControlUnrecorded, Outcome
from agent_bailiff.custodian.backend import BackendError
from agent_bailiff.custodian.files import OwnedFileError
from agent_bailiff.docket.client import DocketError
from agent_bailiff.docket.report import (
    RecordFilter,
    json_row,
    pinned_writers,
    printable,
    table_header,
    table_row,
    verify_records,
)
from agent_bailiff.docket.sink import DocketCorrupt, DocketLocked, VerifiedLine, build_kid_index
from agent_bailiff.effector.catalog import OperationCatalog
from agent_bailiff.effector.drift import RbacDrift
from agent_bailiff.effector.rbac import EffectorIdentity, generate_manifests, parse_tenants, render
from agent_bailiff.keys import PublicKeyRecord
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
    DocketSettings,
    load_control,
    load_custodian,
    load_decide,
    load_docket,
    load_effector,
)
from agent_bailiff.signing import MAX_TOKEN_CHARS

PROG = "agent-bailiff"
EXIT_REFUSED = 1
EXIT_UNRECORDED = 3
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
            verify.add_argument("--task", help="print only records of this task root")
            verify.add_argument("--since", type=int, help="print only records at or after this Unix time (UTC)")
            verify.add_argument("--json", action="store_true", help="print one JSON object per record")
            verify.set_defaults(handler=_verify_docket)
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
            export.set_defaults(handler=_export_docket)
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
    return parser


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
    control = components.add_parser("control")
    control.add_argument("--decide-config", type=Path, required=True)
    effector = components.add_parser("effector")
    effector.add_argument("--custodian-pin", type=Path, required=True, help="the custodian's public key record")
    effector.add_argument("--decide-pin", type=Path, required=True, help="decide's public key record")
    effector.add_argument("--ledger", type=Path, required=True, help="decide's ledger (its suspension is read)")
    effector.add_argument("--ledger-uid", type=int, required=True)
    effector.add_argument("--ledger-group", type=int, required=True)
    effector.add_argument("--port", type=int, required=True, help="127.0.0.1 port the gateway reaches")
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
    docket.add_argument("--reader-group", type=int, help="group that may read the docket (file 0640, dir 0750)")
    docket.add_argument("--allowed-uid", type=int, action="append", required=True, help="writer uid; repeat")
    for parser in (control, docket):
        parser.add_argument("--pin", type=Path, action="append", required=True, help="writer public key record")
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
        )
        return None
    docket = {"socket": args.docket_socket, "sink_uid": args.docket_uid}
    if args.component == "control":
        pins = [read_pin(path) for path in args.pin]
        return init_control(args.dir, name=args.name, decide_config=args.decide_config, pins=pins, docket=docket)
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


def _verify_docket(args: argparse.Namespace) -> int:
    selected = RecordFilter(trace=args.trace, task=args.task, since=args.since)
    shown = 0

    def emit(verified: VerifiedLine) -> None:
        nonlocal shown
        shown += 1
        print(json_row(verified) if args.json else table_row(verified))

    try:
        writers = pinned_writers(read_pin(path) for path in args.pin)
        if not args.json:
            print(table_header())
        report = verify_records(args.docket, writers, selected, emit)
    except STARTUP_ERRORS + (InitError,) as exc:
        return _refused("docket verify", exc)
    if not report.ok:
        print(
            f"{PROG} docket verify: line {report.line} fails verification: {report.reason} {printable(report.detail)}; "
            f"{report.entries} records before it verified, {shown} printed",
            file=sys.stderr,
        )
        if report.reason == "torn_tail":
            print(f"{PROG} docket verify: {TORN_TAIL_HINT}", file=sys.stderr)
        return EXIT_REFUSED
    print(f"{PROG} docket verify: {report.entries} records verified, {shown} printed", file=sys.stderr)
    return 0


def _export_docket(args: argparse.Namespace) -> int:
    try:
        from opentelemetry.exporter.otlp.proto.http.trace_exporter import OTLPSpanExporter
        from opentelemetry.sdk.trace.export import SpanExporter

        from agent_bailiff.docket.otlp import CheckpointMismatch, DocketExporter, ExporterLocked, ExportFailed
    except ImportError:
        return _refused("docket export", ImportError("needs the otel extra: pip install 'agent-bailiff[otel]'"))
    stop = _stop_on_signals()
    try:
        endpoint = _otlp_endpoint(args.otlp)
        index = build_kid_index(pinned_writers(read_pin(path) for path in args.pin))
        span_exporter: SpanExporter = OTLPSpanExporter(endpoint=endpoint, timeout=args.timeout)
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
        )
        exported = exporter.run(stop, follow=not args.once)
    except STARTUP_ERRORS + (CheckpointMismatch, ExportFailed, ExporterLocked) as exc:
        return _refused("docket export", exc)
    finally:
        span_exporter.shutdown()
    print(f"{PROG} docket export: {exported} records exported", file=sys.stderr)
    return 0


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
