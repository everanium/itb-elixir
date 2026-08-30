#!/usr/bin/env bash
#
# run_tests.sh -- one-step test runner for the Elixir binding.
# Builds libitb.so + the C binding archive + the Erlang backend +
# the Mix project via build.sh, then invokes `mix test`. Forwards
# any positional arguments through to mix test (e.g. one file via
# `./run_tests.sh test/smoke_test.exs`).
#
# Usage:
#   ./run_tests.sh                       # full suite
#   ./run_tests.sh test/smoke_test.exs   # one file

set -eu
set -o pipefail

cd "$(dirname "$0")"

./build.sh

if command -v rebar3 > /dev/null; then
    export MIX_REBAR3="${MIX_REBAR3:-$(command -v rebar3)}"
fi

exec mix test --warnings-as-errors "$@"
