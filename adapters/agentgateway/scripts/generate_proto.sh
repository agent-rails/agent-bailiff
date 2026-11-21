#!/bin/sh
set -eu

SHA256=4ba750cca44e9ba68de2ad04e6d507b67f44b1728f09840b78d9e32f3f563584
PYTHON=${PYTHON:-python}
ROOT=$(cd "$(dirname "$0")/../../.." && pwd)
PROTO_DIR="$ROOT/adapters/agentgateway/proto"
OUT=${OUT:-"$ROOT/agent_bailiff/adapters/agentgateway/_proto"}

actual=$("$PYTHON" -c 'import hashlib, sys; print(hashlib.sha256(open(sys.argv[1], "rb").read()).hexdigest())' "$PROTO_DIR/ext_mcp.proto")
if [ "$actual" != "$SHA256" ]; then
    echo "ext_mcp.proto sha256 $actual does not match $SHA256" >&2
    exit 1
fi
rm -rf "$OUT"
mkdir -p "$OUT"
"$PYTHON" -m grpc_tools.protoc -I"$PROTO_DIR" --python_out="$OUT" --pyi_out="$OUT" "$PROTO_DIR/ext_mcp.proto"
: >"$OUT/__init__.py"
