#!/usr/bin/env bash
#
# build.sh -- one-step build for the Elixir binding. Chains the
# Erlang binding's build.sh (libitb.so + the C binding's static
# archive + the NIF shim) and then compiles the Mix project; Mix
# rebuilds the Erlang application as a rebar3 path dependency.
# Prerequisites (Go, a C11 compiler, GNU make, Erlang/OTP 27+,
# rebar3, Elixir 1.17+) must be installed separately; see README.md
# "Prerequisites".
#
# Usage:
#   ./build.sh             # default build (full asm stack)
#   ./build.sh --noitbasm  # opt out of ITB's chain-absorb asm
#   CC=clang ./build.sh    # override the C compiler

set -eu
set -o pipefail

cd "$(dirname "$0")"

../erlang/build.sh "$@"

# Point Mix at the system rebar3 (matching the Erlang binding's
# toolchain) instead of fetching its own copy.
if command -v rebar3 > /dev/null; then
    export MIX_REBAR3="${MIX_REBAR3:-$(command -v rebar3)}"
fi

echo "==> mix compile"
mix compile --warnings-as-errors

echo "==> ready: ./run_tests.sh"
