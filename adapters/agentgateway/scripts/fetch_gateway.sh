#!/bin/sh
set -eu

VERSION=v1.7.0
PINS=$(cd "$(dirname "$0")/.." && pwd)/agentgateway-$VERSION.sha256
case "$(uname -s)-$(uname -m)" in
Darwin-arm64) PLATFORM=darwin-arm64 ;;
Linux-x86_64) PLATFORM=linux-amd64 ;;
*)
	echo "no pinned agentgateway $VERSION binary for $(uname -s)-$(uname -m)" >&2
	exit 1
	;;
esac
NAME=agentgateway-$PLATFORM
SUM=$(grep "  $NAME\$" "$PINS" | cut -d' ' -f1)
CACHE=${AGENT_BAILIFF_CACHE:-${XDG_CACHE_HOME:-$HOME/.cache}/agent-bailiff}/agentgateway/$VERSION
mkdir -p "$CACHE"
cd "$CACHE"
if echo "$SUM  $NAME" | shasum -a 256 -c - >/dev/null 2>&1; then
	echo "$CACHE/$NAME"
	exit 0
fi
download=$(mktemp "$NAME.XXXXXX")
trap 'rm -f "$download"' EXIT
curl --proto '=https' --tlsv1.2 -fsSL -o "$download" "https://github.com/agentgateway/agentgateway/releases/download/$VERSION/$NAME"
echo "$SUM  $download" | shasum -a 256 -c - >/dev/null
chmod 0755 "$download"
mv "$download" "$NAME"
echo "$CACHE/$NAME"
