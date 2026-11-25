#!/bin/sh
set -eu
cd "$(dirname "$0")/.."
export_lock() {
    output=$1
    shift
    uv export --locked --no-dev --no-emit-project --no-emit-workspace --format requirements-txt --quiet "$@" -o "$output"
}
export_lock requirements-ci.txt --extra dev --extra otel
export_lock deploy/kubernetes/webhook-requirements.txt
export_lock examples/quickstart/trace-requirements.txt --extra otel
