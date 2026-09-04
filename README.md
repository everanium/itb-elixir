# ITB Elixir Binding

> **Security notice.** ITB is an experimental symmetric cipher construction without prior peer review, independent cryptanalysis, or formal certification. The construction's security properties have **not been verified** by independent cryptographers or mathematicians.
>
> PRF-grade hash functions are **required**. No warranty is provided.

**No bespoke cryptography.** ITB introduces no cryptographic primitive of its own — no custom S-box, permutation, or round function. It is a construction over existing primitives, much as PGP composes standard ciphers rather than defining one. Such constructions are not the object of algorithm-level cryptographic certification: national regimes (NIST CAVP/FIPS in the US, GOST/FSB in Russia, OSCCA's SM-series in China, IC3S in India, SOG-IS/EUCC and national lists in the EU, ASD's ISM in Australia, CRYPTREC in Japan, KCMVP in South Korea) certify **primitives** and the **modules** built on them, not compositional schemes. Eligibility for regulated use is therefore inherited from the primitives ITB is configured with, not conferred by ITB itself.

Thin proxy over the ITB Erlang binding's Triple Pipeline surface
(`bindings/erlang`) via **native BEAM bytecode interop** — the
Elixir layer calls the Erlang `itb` module directly and adds no FFI
hop of its own. The only native code in the stack is the Erlang
binding's NIF shim, consumed here as a rebar3 path dependency. Every
hash-name / MAC-name / cipher-name / profile-name is an opaque
string passed through to Go for validation; the binding carries no
ITB construction logic. The public surface is the `ITB` module
(`init` / `load` / `load_f` / `save` / `save_f` / `rekey` /
`max_workers` / `free`, Single Message encrypt / decrypt,
incremental stream sessions with `stream_write` / `stream_end` /
`stream_read`, bang variants raising `ITB.Error`), lazy `Stream`
adapters in `ITB.Stream`, the profile catalogue (`inspect` /
`register` / `lookup` / `profiles`), and the Go runtime knobs. Handles are opaque NIF resources; the cipher
entries run on dirty CPU schedulers so multi-megabyte calls never
stall the regular BEAM schedulers.

## Prerequisites (Arch Linux)

```bash
sudo pacman -S go gcc make erlang rebar3 elixir
```

Generic Linux: a Go toolchain, a C11 compiler, GNU make, Erlang/OTP
27+, rebar3, and Elixir 1.17+. macOS: the same via Homebrew; libitb
builds as `libitb.dylib`.

## Build the shared library

The convenience driver builds `libitb.so`, the C binding's static
archive, the Erlang backend (NIF shim included), and the Mix
project in one step:

```bash
./bindings/elixir/build.sh
```

Equivalent manual invocation:

```bash
go build -trimpath -buildmode=c-shared \
    -o dist/linux-amd64/libitb.so ./cmd/cshared
make -C bindings/c build/libitb_c.a
cd bindings/elixir && mix compile
```

## Add to an Elixir project

The binding is a standard Mix project that pulls the Erlang binding
as a rebar3 path dependency. Add both as path dependencies in
`mix.exs`:

```elixir
defp deps do
  [
    {:itb_elixir, path: "/path/to/itb/bindings/elixir"}
  ]
end
```

The compiled NIF (`bindings/erlang/priv/itb_nif.so`) resolves
`libitb.so` through its embedded RPATH into the repo `dist/`
directory, so no `LD_LIBRARY_PATH` is needed at runtime.

## Usage example

```elixir
{:ok, sender} = ITB.init("singlemsg-triple-mac-v1")
{:ok, blob} = ITB.save(sender)
{:ok, receiver} = ITB.load(blob)

{:ok, wire} = ITB.encrypt_message(sender, "any text or binary data")
{:ok, plain} = ITB.decrypt_message(receiver, wire)

:ok = ITB.free(receiver)
:ok = ITB.free(sender)

# File-backed equivalent (persist across processes):
# {:ok, sender} = ITB.init("singlemsg-triple-mac-v1")
# :ok = ITB.save_f(sender, "session.blob")
# {:ok, receiver} = ITB.load_f("session.blob")
```

Opts override the profile default at `ITB.init` (chunk size, outer
cipher, parallax on/off, wrapper on/off, MAC name, palette, worker
cap) as a map or keyword list. The resolved shape is written into
the blob, so the receiver loads it with no opts of its own:

```elixir
opts = %{"chunkSize" => 65536, "withWrapper" => false}
{:ok, sender} = ITB.init("singlemsg-triple-mac-v1", opts)
{:ok, blob} = ITB.save(sender)
{:ok, receiver} = ITB.load(blob)
```

`ITB.rekey/3` rotates the parallax + wrapper masters mid-session
(the eight ITB seeds and MAC key are fixed for the session lifetime
by design) and returns the refreshed blob; the receiver picks up the
new masters through a fresh `ITB.load/1`:

```elixir
{:ok, blob2} = ITB.rekey(sender, :binary.copy(<<0x11>>, 32), :binary.copy(<<0x22>>, 32))
{:ok, receiver2} = ITB.load(blob2)
```

## Persisting sessions

The blob is self-describing: it carries the profile record (mode,
width, primitives, key bits, MAC, layer switches) alongside the key
material, so a session reopens from the blob alone.

```elixir
{:ok, blob} = ITB.save(sender)                 # current blob (binary)
:ok = ITB.save_f(sender, "session.blob")       # written by libitb, mode 0600
{:ok, receiver} = ITB.load(blob)               # reopen from bytes
{:ok, receiver} = ITB.load_f("session.blob")   # reopen from file
{:ok, receiver} = ITB.load(blob, perm, wrap)   # override the masters
{:ok, record} = ITB.inspect(blob)              # profile record, no Pipeline
```

`ITB.inspect/1` returns the record as a map decoded with the OTP
`json` module (binary keys `"name"`, `"mode"`, `"width"`, `"hash"`,
`"hashes"`, `"keybits"`, `"mac"`, `"tagstub"`, `"chunk"`,
`"wrapper"`, `"outer"`, `"parallax"`, `"palette"`, `"segment"`;
absent keys are optional fields at their zero value).

The shipped `itb3` command-line utility (see `cmd/itb3`) generates
session blobs on disk (JSON files) that this binding reopens through
`ITB.load_f/1`, and also encrypts / decrypts files or stdio streams
from the shell. It is the openssl-style entry point for ITB; the
binding is the programmatic entry point.

Load works for blobs generated with shipped primitives (every entry
in the shipped catalogue). Blobs generated by Go programs that use
`hashes.Register` or `macs.Register` to install custom primitives
cannot be loaded through this binding — the receiver must use the Go
library directly and register the same custom primitive under the
same name before opening. Attempting to `ITB.load/1` such a blob
through this binding returns `{:error, {:recipe_primitive_unknown, _}}`.

## Profile registry

```elixir
ITB.profiles()                                 # sorted list of binaries
ITB.lookup("singlemsg-triple-mac-v1")          # {:ok, record}; unknown -> :unknown_profile
:ok = ITB.register("my-profile", %{
  mode: "singlemsg-nomac",
  width: 256,
  hashes: ~w(blake3 blake2s areion256 blake2b256 chacha20 blake3 blake2s areion256),
  keybits: 1024,
  parallax: false,
  wrapper: false
})
{:ok, sender} = ITB.init("my-profile")
```

`ITB.register/2` takes the same record shape `inspect` / `lookup`
return (a map with atom or binary keys, or an already-encoded JSON
binary); a `name` key inside it, if present, must be empty or equal
to the name argument. Every rule — name pattern, reserved prefixes,
field constraints, primitive names — is enforced by libitb; a
duplicate name returns `{:error, {:profile_exists, _}}`.

## Runtime tuning

`ITB.max_workers/2` sets the worker cap on a live Pipeline (`n <= 0`
selects auto, values above 256 are clamped). The cap is per-machine
tuning and is never written to the blob, so the receiver may pick
its own worker cap after `ITB.load/1`. The `maxWorkers` opts key
sets the same cap at `ITB.init/2`.

Every tuple-returning function has a bang variant that unwraps the
result or raises `ITB.Error` (carrying the same status atom +
diagnostic):

```elixir
sender = ITB.init!("singlemsg-triple-mac-v1")
wire = ITB.encrypt_message!(sender, "payload")
```

### One-shot streams

`ITB.encrypt_stream_one_shot/2` / `ITB.decrypt_stream_one_shot/2`
(plus bang variants) put a whole in-memory payload through the
stream chain in a single call:

```elixir
{:ok, wire} = ITB.encrypt_stream_one_shot(sender, plain)
{:ok, plain} = ITB.decrypt_stream_one_shot(receiver, wire)
```

### Lazy Stream adapters

`ITB.stream_encrypt/3` / `ITB.stream_decrypt/3` (sugar over
`ITB.Stream`) wrap one incremental session into a lazy Elixir
`Stream` over any enumerable of chunks — memory stays bounded by
the chunk and drain-slice sizes regardless of total payload length:

```elixir
File.stream!("plain.bin", 1_048_576)
|> then(&ITB.stream_encrypt(sender, &1))
|> Stream.into(File.stream!("wire.bin"))
|> Stream.run()
```

The session opens when consumption starts and is released on every
termination path (exhaustion, raise, downstream halt); failures
raise `ITB.Error` from the consuming process, since a lazy stream
has no channel for error tuples.

### Caller-driven sessions

For explicit loops, the session surface mirrors the Erlang binding:

```elixir
{:ok, session} = ITB.encrypt_stream(sender)
:ok = ITB.stream_write(session, chunk1)
:ok = ITB.stream_write(session, chunk2)
:ok = ITB.stream_end(session)
# Drain until {:ok, data, true}:
{:ok, wire_piece, finished} = ITB.stream_read(session, 1_048_576)
:ok = ITB.stream_free(session)
```

Profile names, opts keys, and every primitive name are validated by
the Go side; a rejected string surfaces as
`{:error, {status, detail}}` — `status` an atom mirroring the C
binding's status table (e.g. `:mac_failure`, `:bad_input`,
`:profile_exists`), `detail` the Go-side diagnostic binary. Opts
are a map or keyword list (`%{keyBits: 1024, nonceBits: 512}`)
rendered into the URL-query string libitb consumes.

Handle lifetime is garbage-collected: dropping every term reference
releases the Go-side state through the NIF resource destructor, and
`ITB.free/1` / `ITB.stream_free/1` release eagerly (both
idempotent). A stream session pins its parent pipeline resource, so
the pipeline is never collected under a live session.

## Memory

Two process-wide knobs constrain Go runtime arena pacing, readable
at libitb load time via env vars (`ITB_GOMEMLIMIT`, `ITB_GOGC`) and
adjustable at any time programmatically. Pass `-1` to query without
changing. Long-running or allocation-heavy workloads (benchmarks,
bulk encryption) should set both — without a soft cap + aggressive
GC the Go scratch heap grows unboundedly under allocation churn:

```elixir
ITB.set_memory_limit(512 * 1024 * 1024) # 512 MiB soft cap
ITB.set_gc_percent(20)                  # aggressive GC
```

## Testing

```bash
./bindings/elixir/run_tests.sh
```

The harness builds `libitb.so` + the C archive + the Erlang backend
+ the Mix project, then invokes `mix test`. Positional arguments
are forwarded to mix test (e.g. `./run_tests.sh
test/smoke_test.exs`). The suite covers Single Message round trips
per shipped profile, stream pumps, incremental sessions with
pathological batch sizes, lazy `Stream` adapters, tampered-wire
failure stickiness, mid-flight cancellation, garbage-collection
backstop release, rekey, profile registration, and error mapping —
surface parity checks; the deep suite lives in Go under the shipped
tree.

## Benchmarking

```bash
./bindings/elixir/run_bench.sh
```

Micro-benches: `message` (encrypt_message) and `stream_pump`
(incremental encrypt session) throughput at 1 MiB / 16 MiB /
64 MiB, reported as an MB/s table on stdout. The runner exports
`ITB_GOMEMLIMIT=512MiB` + `ITB_GOGC=20` defaults (respecting caller
overrides) and the bench scripts apply the same caps
programmatically. `./run_bench.sh message` / `./run_bench.sh
stream` runs one shape.

## eitb utility

An executable Elixir script under `bindings/elixir/eitb/` mirrors
the shipped Go `tools/eitb` scope for shell smoke tests (build the
binding first):

```bash
cd bindings/elixir
./eitb/eitb version
./eitb/eitb profiles
./eitb/eitb inspect <blob-hex>
./eitb/eitb encrypt singlemsg-triple-mac-v1 in.bin out.bin  # blob hex on stderr
./eitb/eitb decrypt singlemsg-triple-mac-v1 <blob-hex> out.bin back.bin
```

## Limitations

- The binding wraps the Triple Pipeline surface only. The Low-Level
  seed / MAC / blob / wrapper / parallax APIs are not exposed — use
  the shipped Go core for those.
- Streaming-decrypt caveat: chunked Streaming AEAD verifies per
  chunk, so plaintext of verified chunks is released before a later
  chunk can fail authentication. The lazy `ITB.Stream.decrypt/3`
  adapter inherits this: verified plaintext is emitted before a
  later chunk can raise.
- The `detail` text in an error tuple comes from a process-global
  last-write-wins store on the Go side; under concurrent use it may
  belong to a different call. The status atom is always
  attributable.
- `ITB.rekey/3` must not run concurrently with cipher calls or open
  stream sessions on the same Pipeline.
- Single-owner discipline per handle: do not call `ITB.free/1` /
  `ITB.stream_free/1` while another process is mid-call on the same
  handle — free from the owning process, or drop every reference
  and let the resource destructor release.
- After `ITB.stream_end/1`, an empty-spool `ITB.stream_read/2`
  blocks (on a dirty scheduler) until the terminal bytes arrive or
  the session errors; the regular schedulers are unaffected.
- A downstream halt of a lazy encrypt stream cancels the session
  rather than finalising it — the emitted prefix is not a
  decryptable wire.
