#!/bin/sh
set -eu

COMMIT=26f5aebe99a36a037fe54f8080a608aca5547e15
SHA256=4ba750cca44e9ba68de2ad04e6d507b67f44b1728f09840b78d9e32f3f563584
URL="https://raw.githubusercontent.com/agentgateway/agentgateway/$COMMIT/crates/protos/proto/ext_mcp.proto"
PYTHON=${PYTHON:-python}
ROOT=$(cd "$(dirname "$0")/../../.." && pwd)
OUT="$ROOT/agent_bailiff/adapters/agentgateway/_proto"

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
curl --proto '=https' --tlsv1.2 -fsSL -o "$work/ext_mcp.proto" "$URL"
echo "$SHA256  $work/ext_mcp.proto" | shasum -a 256 -c - >/dev/null
rm -rf "$OUT"
mkdir -p "$OUT"
"$PYTHON" -m grpc_tools.protoc -I"$work" --python_out="$OUT" --pyi_out="$OUT" "$work/ext_mcp.proto"
: >"$OUT/__init__.py"
