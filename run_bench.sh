#!/usr/bin/env bash
#
# run_bench.sh -- micro-benchmark runner for the Elixir binding.
# Builds libitb.so + the C binding archive + the Erlang backend +
# the Mix project via build.sh, then runs bench_message, bench_stream
# and bench_stream_one_shot: encrypt_message, stream-pump and
# whole-buffer stream throughput at 1 MiB / 16 MiB / 64 MiB.
#
# Usage:
#   ./run_bench.sh                        # all shapes
#   ./run_bench.sh message                # Single Message shape only
#   ./run_bench.sh stream                 # stream-pump shape only
#   ./run_bench.sh stream_one_shot        # whole-buffer stream shape only

set -eu
set -o pipefail

cd "$(dirname "$0")"

./build.sh

if command -v rebar3 > /dev/null; then
    export MIX_REBAR3="${MIX_REBAR3:-$(command -v rebar3)}"
fi

# Go-runtime pacing defaults for bench-scale allocation churn; the
# `:-` form respects any override set by the caller. The bench mains
# apply the same caps programmatically.
export ITB_GOMEMLIMIT="${ITB_GOMEMLIMIT:-512MiB}"
export ITB_GOGC="${ITB_GOGC:-20}"

# Bench-shape defaults — match the root Go BENCH3.md pin so the
# throughput numbers are directly comparable to the shipped Go
# Encrypt3x{128,256,512}Cfg baseline. Override any of these before
# calling the script to change the shape.
export ITB_NONCE_BITS="${ITB_NONCE_BITS:-512}"
export ITB_KEY_BITS="${ITB_KEY_BITS:-1024}"
export ITB_WITH_PARALLAX="${ITB_WITH_PARALLAX:-false}"
export ITB_WITH_WRAPPER="${ITB_WITH_WRAPPER:-false}"
export ITB_INNER_HASH="${ITB_INNER_HASH:-areion512}"
export ITB_BENCH_MIN_SEC="${ITB_BENCH_MIN_SEC:-5}"

# ITB_WITH_MAC=true derives MAC/AEAD profile counterparts. When
# ITB_PROFILE is set explicitly by the caller, it wins over the
# derivation and applies to both shapes (expert override).
: "${ITB_WITH_MAC:=false}"
if [ -n "${ITB_PROFILE:-}" ]; then
    ITB_MSG_PROFILE_DEFAULT="${ITB_PROFILE}"
    ITB_STREAM_PROFILE_DEFAULT="${ITB_PROFILE}"
elif [ "${ITB_WITH_MAC}" = "true" ]; then
    ITB_MSG_PROFILE_DEFAULT="singlemsg-triple-mac-v1"
    ITB_STREAM_PROFILE_DEFAULT="streaming-aead-triple-mac-v1"
else
    ITB_MSG_PROFILE_DEFAULT="singlemsg-triple-nomac-v1"
    ITB_STREAM_PROFILE_DEFAULT="streaming-noaead-triple-v1"
fi

WHAT="${1:-all}"

case "$WHAT" in
    message)        export ITB_PROFILE="${ITB_MSG_PROFILE_DEFAULT}"
                    mix run bench/bench_message.exs;;
    stream)         export ITB_PROFILE="${ITB_STREAM_PROFILE_DEFAULT}"
                    mix run bench/bench_stream.exs;;
    stream_one_shot)
                    export ITB_PROFILE="${ITB_STREAM_PROFILE_DEFAULT}"
                    mix run bench/bench_stream_one_shot.exs;;
    all)            export ITB_PROFILE="${ITB_MSG_PROFILE_DEFAULT}"
                    mix run bench/bench_message.exs
                    export ITB_PROFILE="${ITB_STREAM_PROFILE_DEFAULT}"
                    mix run bench/bench_stream.exs
                    mix run bench/bench_stream_one_shot.exs;;
    *)              echo "usage: $0 [message|stream|stream_one_shot|all]" >&2
                    exit 2;;
esac
