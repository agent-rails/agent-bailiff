from __future__ import annotations

import argparse
import json
import logging
import sys
from pathlib import Path
from typing import Any

from agent_bailiff.effector.catalog import OperationCatalog
from agent_bailiff.effector.kubernetes import HttpsTransport, read_token
from agent_bailiff.effector.rbac import parse_tenants
from agent_bailiff.effector.release import ReleaseCheckConfig
from agent_bailiff.keys import parse_pinned_keys
from agent_bailiff.service.init import DEFAULT_CATALOG
from agent_bailiff.strict_json import parse_strict_json
from agent_bailiff.webhook.admission import Admission
from agent_bailiff.webhook.audit import WebhookAudit
from agent_bailiff.webhook.certs import issue_serving_certificate
from agent_bailiff.webhook.manifests import NAME, generate_manifests
from agent_bailiff.webhook.server import WebhookServer


def _pins(path: Path) -> dict[str, Any]:
    value = parse_strict_json(path.read_bytes())
    if not isinstance(value, dict):
        raise ValueError("pins must be an object")
    return value


def _admission(config: dict[str, Any], catalog: OperationCatalog, *, enforce: bool | None = None) -> Admission:
    required = {
        "effector_id",
        "custodian_id",
        "decider_id",
        "custodian_keys",
        "decide_keys",
        "catalog_digest",
        "skew_seconds",
        "max_clearance_lifetime",
        "enforce",
    }
    if set(config) != required or config["catalog_digest"] != catalog.digest:
        raise ValueError("webhook config fields or catalog digest do not match")
    for name in ("effector_id", "custodian_id", "decider_id"):
        if not isinstance(config[name], str) or not config[name]:
            raise ValueError(f"{name} must be a nonempty string")
    if not isinstance(config["enforce"], bool):
        raise ValueError("enforce must be a boolean")
    if type(config["skew_seconds"]) is not int or config["skew_seconds"] not in (0, 1, 2):
        raise ValueError("skew_seconds must be 0..2")
    if type(config["max_clearance_lifetime"]) is not int or config["max_clearance_lifetime"] < 1:
        raise ValueError("max_clearance_lifetime must be a positive integer")
    checks = ReleaseCheckConfig(
        effector_id=config["effector_id"],
        custodian_id=config["custodian_id"],
        decider_id=config["decider_id"],
        custodian_keys=parse_pinned_keys(config["custodian_id"], config["custodian_keys"]),
        decide_keys=parse_pinned_keys(config["decider_id"], config["decide_keys"]),
        skew_seconds=config["skew_seconds"],
        max_clearance_lifetime=config["max_clearance_lifetime"],
    )
    return Admission(checks, catalog, enforce=config["enforce"] if enforce is None else enforce)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="agent-bailiff-webhook")
    commands = parser.add_subparsers(dest="command", required=True)
    certs = commands.add_parser("certs")
    certs.add_argument("--namespace", required=True)
    certs.add_argument("--output-dir", type=Path, required=True)
    manifests = commands.add_parser("manifests")
    manifests.add_argument("--namespace", required=True)
    manifests.add_argument("--image", required=True)
    manifests.add_argument("--ca", type=Path, required=True)
    manifests.add_argument("--pins", type=Path, required=True)
    manifests.add_argument("--catalog", type=Path, default=DEFAULT_CATALOG)
    manifests.add_argument("--enforce", action="store_true")
    manifests.add_argument(
        "--phase",
        choices=("all", "prepare", "register", "target"),
        default="all",
        help="stage an Enforce transition: prepare pods, register the policy, or render a full audit target",
    )
    serve = commands.add_parser("serve")
    serve.add_argument("--config", type=Path, required=True)
    serve.add_argument("--catalog", type=Path, default=DEFAULT_CATALOG)
    serve.add_argument("--cert", type=Path, required=True)
    serve.add_argument("--key", type=Path, required=True)
    serve.add_argument("--mode", choices=("audit", "enforce"), required=True)
    serve.add_argument("--host", default="0.0.0.0")
    serve.add_argument("--port", type=int, default=9443)
    audit = commands.add_parser("audit")
    audit.add_argument("--manifest", type=Path, required=True)
    audit.add_argument("--kube-host", required=True)
    audit.add_argument("--kube-port", type=int, default=443)
    audit.add_argument("--kube-ca", type=Path, required=True)
    audit.add_argument("--token-file", type=Path, required=True)
    audit.add_argument("--effector-namespace", required=True)
    audit.add_argument("--effector-account", required=True)
    audit.add_argument("--tenant", action="append", required=True)
    args = parser.parse_args(argv)
    logging.basicConfig(level=logging.INFO)
    if args.command == "certs":
        issue_serving_certificate(args.output_dir, NAME, args.namespace)
        return 0
    if args.command == "audit":
        manifest = _pins(args.manifest)
        users = [
            f"bailiff:{tenant}:{identity}"
            for tenant in parse_tenants(args.tenant)
            for identity in ("read", "scale", "restart")
        ]
        audit_check = WebhookAudit(
            HttpsTransport(args.kube_host, args.kube_port, args.kube_ca),
            read_token(args.token_file),
            manifest,
            args.effector_namespace,
            args.effector_account,
            users,
        )
        problems = audit_check.check()
        for problem in problems:
            print(problem)
        return 1 if problems else 0
    catalog = OperationCatalog.load(args.catalog)
    if args.command == "manifests":
        if args.enforce and args.phase == "all":
            parser.error("--enforce requires --phase prepare, register, or target; do not apply Enforce as one bundle")
        pins = _pins(args.pins)
        _admission({**pins, "enforce": args.enforce}, catalog)
        generated = generate_manifests(
            namespace=args.namespace,
            image=args.image,
            ca_pem=args.ca.read_bytes(),
            pins=pins,
            catalog=catalog,
            enforce=args.enforce,
            phase=args.phase,
        )
        if args.enforce and args.phase == "target":
            print(
                "Target bundle is for audit comparison only; apply prepare then register as separate phases.",
                file=sys.stderr,
            )
        print(json.dumps(generated, indent=2, sort_keys=True))
        return 0
    admission = _admission(_pins(args.config), catalog, enforce=args.mode == "enforce")
    with WebhookServer(admission, args.host, args.port, args.cert, args.key) as server:
        server.serve_forever()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
