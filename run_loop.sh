#!/usr/bin/env bash
#
# Fleet entry point for the loop stress harness of the Elixir binding:
# compiles the utility's modules (libitb3.so, the NIF shim, the Erlang
# backend and the Mix project are assumed built by build.sh) and execs
# it with every argument passed through.
#
# Usage:
#   ./run_loop.sh --duration 2m --shape both

set -eu
set -o pipefail

cd "$(dirname "$0")"

BUILD="$PWD/_build/dev/lib"
if [ ! -d "$BUILD/libitb3_elixir/ebin" ]; then
    echo "run_loop.sh: binding not compiled, run ./build.sh first: $BUILD" >&2
    exit 1
fi

elixirc --warnings-as-errors \
        -pa "$BUILD/libitb3/ebin" -pa "$BUILD/libitb3_elixir/ebin" \
        -o loop loop/*.ex

exec ./loop/loop "$@"
