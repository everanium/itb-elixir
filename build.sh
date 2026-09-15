#!/usr/bin/env bash
#
# build.sh -- one-step build for the Elixir binding. Chains the
# Erlang binding's build.sh (libitb3.so + the C binding's static
# archive + the NIF shim) and then compiles the Mix project; Mix
# rebuilds the Erlang application as a rebar3 path dependency.
# Prerequisites (Go, a C11 compiler, GNU make, Erlang/OTP 27+,
# rebar3, Elixir 1.17+) must be installed separately; see README.md
# "Prerequisites".
#
# The build starts by removing every artefact this binding owns, so no
# output of an earlier build can survive into this one and mask a
# breakage. The chained Erlang build.sh wipes the backend the same way,
# so the whole BEAM stack is rebuilt from tracked sources.
# ITB_SKIP_CLEAN=1 keeps both trees for fast iteration.
#
# Usage:
#   ./build.sh                       # default build (full asm stack)
#   ./build.sh --noitbasm            # opt out of ITB's SIMD asm kernels
#   CC=clang ./build.sh              # override the C compiler
#   ITB_SKIP_CLEAN=1 ./build.sh      # incremental build, no wipe

set -eu
set -o pipefail

cd "$(dirname "$0")"
SCRIPT_DIR="$(pwd)"
REPO_ROOT="$(cd ../.. && pwd)"

# Answered before the wipe below, so asking for usage never removes
# anything. Every other argument is forwarded to the Erlang build.
case "${1:-}" in
    -h|--help) echo "usage: $0 [--noitbasm]"; exit 0;;
esac

# ---------------------------------------------------------------------
# Artefact wipe.
#
# ARTEFACTS names what this binding generates. Inside a git work tree
# the list is supplemented from `git ls-files --others --ignored`, which
# enumerates exactly the paths .gitignore covers and by construction can
# never name a tracked one. Every candidate is canonicalised and refused
# unless it resolves inside this binding's own directory.
#
# The Erlang backend under ../erlang is depended on, never removed from
# here: the chained build.sh below owns that tree's wipe.
# ---------------------------------------------------------------------
ARTEFACTS=(
    _build
    deps
    .mix
    .elixir_ls
    .elixir-tools
    erl_crash.dump
    '*.beam'
    '*.ez'
)

# Containment is checked against the physical path, so the candidate
# and the root are canonicalised the same way even when the checkout is
# reached through a symlinked directory.
CLEAN_ROOT="$(readlink -m -- "$SCRIPT_DIR")"

rm_artefact() {
    local rel="$1" abs
    abs="$(readlink -m -- "$CLEAN_ROOT/$rel")"
    case "$abs" in
        "$CLEAN_ROOT"/?*) ;;
        *) echo "clean: '$rel' resolves outside $CLEAN_ROOT ($abs)" >&2
           exit 1 ;;
    esac
    [ -e "$abs" ] || return 0
    echo "[clean] rm -rf $abs"
    rm -rf -- "$abs"
}

clean_artefacts() {
    local entry match
    shopt -s nullglob
    for entry in "${ARTEFACTS[@]}"; do
        for match in "$CLEAN_ROOT"/$entry; do
            rm_artefact "${match#"$CLEAN_ROOT"/}"
        done
    done
    shopt -u nullglob
    # The work-tree probe silences stderr because a source tarball
    # carries no git metadata; there the ARTEFACTS list stands alone.
    if git -C "$CLEAN_ROOT" rev-parse --is-inside-work-tree >/dev/null 2>&1
    then
        while IFS= read -r entry; do
            [ -n "$entry" ] || continue
            # A dot-prefixed .md is a private note kept out of the index
            # by the global ignore file, not build output.
            case "${entry##*/}" in .*.md) continue;; esac
            rm_artefact "$entry"
        done < <(git -C "$CLEAN_ROOT" ls-files --others --ignored \
                     --exclude-standard --directory)
    fi
}

if [ "${ITB_SKIP_CLEAN:-0}" = "1" ]; then
    echo "==> ITB_SKIP_CLEAN=1 -- keeping existing build artefacts"
else
    echo "==> removing build artefacts"
    clean_artefacts
fi

../erlang/build.sh "$@"

# Point Mix at the system rebar3 (matching the Erlang binding's
# toolchain) instead of fetching its own copy.
if command -v rebar3 > /dev/null; then
    export MIX_REBAR3="${MIX_REBAR3:-$(command -v rebar3)}"
fi

echo "==> mix compile"
mix compile --warnings-as-errors

# eitb is an `elixir` script: it is parsed and compiled on every
# invocation and so cannot carry a stale compilation of its own.
# Running `version` here proves it parses and resolves the _build
# ebin directories just compiled -- the failure mode a pre-compiled
# launcher would hide.
echo "==> eitb"
ITB_LIBITB3_PATH="$REPO_ROOT/dist/linux-amd64/libitb3.so" \
LD_LIBRARY_PATH="$REPO_ROOT/dist/linux-amd64${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}" \
    ./eitb/eitb version

echo "==> ready: ./run_tests.sh"
