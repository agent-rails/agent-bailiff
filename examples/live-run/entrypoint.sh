#!/bin/sh
set -eu

fail() {
	echo "entrypoint: $*" >&2
	exit 1
}

: "${ROOT:?ROOT must be set}" "${ARCHIVER_UID:?ARCHIVER_UID must be set}" "${SCRIPT:?SCRIPT must be set}"
case "$SCRIPT" in
run.py | kubernetes.py) ;;
*) fail "SCRIPT must be run.py or kubernetes.py, not $SCRIPT" ;;
esac
case "$ARCHIVER_UID" in
'' | *[!0-9]*) fail "ARCHIVER_UID must be a uid, not $ARCHIVER_UID" ;;
esac
[ "$ARCHIVER_UID" -ne "$(id -u bailiff)" ] || fail "ARCHIVER_UID $ARCHIVER_UID is the harness uid"
[ "$(id -u)" -eq 0 ] || fail "must start as root"

[ ! -L "$ROOT" ] || fail "$ROOT must not be a link"
fstype=$(awk -v root="$ROOT" '$5 == root { for (i = 6; i <= NF; i++) if ($i == "-") { print $(i + 1); exit } }' /proc/self/mountinfo)
[ "$fstype" = tmpfs ] || fail "$ROOT must be a tmpfs mount, found ${fstype:-no mount}"
[ -z "$(ls -A "$ROOT")" ] || fail "$ROOT must be empty"

IFS=' ' read -r token_length kubeconfig_length || fail "stdin bundle has no header"
case "$token_length$kubeconfig_length" in
'' | *[!0-9]*) fail "stdin bundle header must be two lengths" ;;
esac
[ "$token_length" -gt 0 ] || fail "stdin bundle has no token"
if [ "$SCRIPT" = kubernetes.py ]; then
	[ "$kubeconfig_length" -gt 0 ] || fail "kubernetes.py needs a kubeconfig in the stdin bundle"
else
	[ "$kubeconfig_length" -eq 0 ] || fail "run.py takes no kubeconfig"
fi

chmod 0755 "$ROOT"
mkdir -m 0750 "$ROOT/receipts"
chown "$ARCHIVER_UID:bailiff" "$ROOT/receipts"
work=$ROOT/work
mkdir -m 0700 "$work" "$work/home"
umask 077
head -c "$token_length" >"$work/claude-token"
[ "$(wc -c <"$work/claude-token")" -eq "$token_length" ] || fail "stdin bundle token is truncated"
if [ "$kubeconfig_length" -gt 0 ]; then
	head -c "$kubeconfig_length" >"$work/kubeconfig"
	[ "$(wc -c <"$work/kubeconfig")" -eq "$kubeconfig_length" ] || fail "stdin bundle kubeconfig is truncated"
fi
chown -R bailiff:bailiff "$work"

export KUBECONFIG="$work/kubeconfig" HOME="$work/home"
exec setpriv --reuid bailiff --regid bailiff --init-groups --inh-caps=-all --no-new-privs -- \
	python -E -s "/app/examples/live-run/$SCRIPT" --root "$work" --receipt-dir "$ROOT/receipts" \
	--archiver-uid "$ARCHIVER_UID" "$@" </dev/null
