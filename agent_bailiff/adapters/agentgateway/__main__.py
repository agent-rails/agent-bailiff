from __future__ import annotations

import argparse
import sys
from collections.abc import Sequence
from pathlib import Path
from typing import Any

from agent_bailiff.adapters.agentgateway.calls import ToolRoutes, parse_strict_json
from agent_bailiff.adapters.agentgateway.config_check import GatewayExpectations, validate_gateway_config
from agent_bailiff.custodian.bindings import BindingTable
from agent_bailiff.custodian.files import OwnedFileError

MAX_CONFIG_BYTES = 1 << 20


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="python -m agent_bailiff.adapters.agentgateway")
    commands = parser.add_subparsers(dest="command", required=True)
    check = commands.add_parser("check-config", help="refuse an agentgateway config the processors cannot enforce")
    check.add_argument("--gateway-config", type=Path, required=True, help="agentgateway config file, in JSON")
    check.add_argument("--routes", type=Path, required=True, help="route table shared by both processors")
    check.add_argument("--bindings", type=Path, required=True, help="custodian binding table (run as its owner)")
    check.add_argument("--decide-socket", type=Path, required=True)
    check.add_argument("--custodian-socket", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        document = _load_json(args.gateway_config, "gateway config")
        routes = ToolRoutes.from_document(_load_json(args.routes, "route table"))
        bindings = BindingTable.load(args.bindings)
        expected = GatewayExpectations(
            decide_socket=args.decide_socket,
            custodian_socket=args.custodian_socket,
            services=routes.services,
            credential_headers=frozenset(binding.header_name for binding in bindings.bindings),
        )
    except (OSError, ValueError, OwnedFileError) as exc:
        print(f"check-config refused: {exc}", file=sys.stderr)
        return 1
    problems = validate_gateway_config(document, expected)
    for problem in problems:
        print(f"check-config refused: {problem}", file=sys.stderr)
    if problems:
        return 1
    print("ok")
    return 0


def _load_json(path: Path, label: str) -> Any:
    with open(path, "rb") as source:
        raw = source.read(MAX_CONFIG_BYTES + 1)
    if len(raw) > MAX_CONFIG_BYTES:
        raise ValueError(f"the {label} is larger than {MAX_CONFIG_BYTES} bytes")
    try:
        return parse_strict_json(raw)
    except (ValueError, UnicodeDecodeError) as exc:
        raise ValueError(f"the {label} is not valid JSON: {exc}") from None


if __name__ == "__main__":
    sys.exit(main())
