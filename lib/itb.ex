defmodule ITB do
  @moduledoc """
  Public API of the ITB Elixir binding.

  Thin proxy over the ITB Erlang binding's `itb` module via native
  BEAM bytecode interop — the Elixir layer adds no FFI hop of its
  own. No ITB construction logic lives in this binding: profile
  names, opts keys, and every primitive name are opaque strings
  passed through to Go for validation.

  Quick start:

      {:ok, sender} = ITB.init("singlemsg-triple-mac-v1")
      {:ok, blob} = ITB.save(sender)
      {:ok, receiver} = ITB.load(blob)
      {:ok, wire} = ITB.encrypt_message(sender, "hi")
      {:ok, "hi"} = ITB.decrypt_message(receiver, wire)
      :ok = ITB.free(receiver)
      :ok = ITB.free(sender)

  Handles are opaque NIF resources owned by the Erlang layer:
  dropping every term reference lets the garbage collector release
  the Go-side state (libitb zeroes key material internally), and
  `free/1` / `stream_free/1` release eagerly. A stream session pins
  its parent pipeline, so the pipeline can never be collected under
  a live session. Do not call `free/1` on a handle another process
  is concurrently using — single-owner discipline per handle, or
  drop references and let the collector free.

  Errors follow the `{:ok, result} | {:error, {status, detail}}`
  idiom: `status` is an `ITB.Status.t()` atom and `detail` the
  Go-side diagnostic binary. Every tuple-returning function has a
  bang variant (`init!/2`, `encrypt_message!/2`, ...) that unwraps
  the result or raises `ITB.Error`.

  Lazy chunk-by-chunk processing over any enumerable is available
  as `stream_encrypt/3` / `stream_decrypt/3` (see `ITB.Stream`);
  the caller-driven session surface (`encrypt_stream/1`,
  `stream_write/2`, `stream_end/1`, `stream_read/2`) is the
  explicit-loop alternative.
  """

  @typedoc "Opaque NIF resource for a Triple Pipeline session."
  @type pipeline :: reference()

  @typedoc "Opaque NIF resource for an incremental stream session."
  @type stream :: reference()

  @typedoc """
  Opts accumulate into the URL-query string consumed by libitb; the
  binding performs no validation — Go rejects unknown keys and bad
  values with a diagnostic in the error detail. Keyword lists, maps,
  and mixed atom / binary keys are all accepted; values may be
  atoms, binaries, integers, or booleans.
  """
  @type opts :: map() | keyword() | [{atom() | binary(), atom() | binary() | integer()}]

  @typedoc "Error payload: status atom plus Go-side diagnostic."
  @type reason :: {ITB.Status.t(), binary()}

  @typedoc """
  Profile record: the JSON object libitb emits from `inspect/1` /
  `lookup/1` and accepts in `register/2`, decoded with the OTP `json`
  module (binary keys `"name"`, `"mode"`, `"width"`, `"hash"`,
  `"hashes"`, `"keybits"`, `"mac"`, `"tagstub"`, `"chunk"`,
  `"wrapper"`, `"outer"`, `"parallax"`, `"palette"`, `"segment"`;
  absent keys are optional fields at their zero value).
  """
  @type profile :: %{optional(binary() | atom()) => term()}

  # `inspect/1` below is the blob-record decoder, not Kernel.inspect.
  import Kernel, except: [inspect: 1, inspect: 2]

  # Default drain slice for stream_read/1 (1 MiB).
  @read_buf 1_048_576

  # ------------------------------------------------------------------
  # Pipeline lifecycle
  # ------------------------------------------------------------------

  @doc """
  Constructs a fresh Pipeline against the named profile. Opts may be
  omitted for pure profile defaults. The session blob is available
  through `save/1`.
  """
  @spec init(iodata() | atom(), opts()) :: {:ok, pipeline()} | {:error, reason()}
  def init(profile, opts \\ %{}), do: :itb.init(profile, opts)

  @doc "As `init/2`, unwrapping the pipeline or raising `ITB.Error`."
  @spec init!(iodata() | atom(), opts()) :: pipeline()
  def init!(profile, opts \\ %{}), do: bang(init(profile, opts))

  @doc """
  Reconstructs a Pipeline from a blob produced by `save/1` or
  `rekey/3`. The blob's embedded profile record is the sole
  structural source — no profile name, no opts. `perm_master` /
  `wrap_master` override the blob-embedded masters when both are
  supplied (a half-supplied pair is rejected Go-side); the defaults
  `<<>>` / `<<>>` select the blob-embedded masters.
  """
  @spec load(binary(), binary(), binary()) :: {:ok, pipeline()} | {:error, reason()}
  def load(blob, perm_master \\ <<>>, wrap_master \\ <<>>),
    do: :itb.load(blob, perm_master, wrap_master)

  @doc "As `load/3`, unwrapping the pipeline or raising `ITB.Error`."
  @spec load!(binary(), binary(), binary()) :: pipeline()
  def load!(blob, perm_master \\ <<>>, wrap_master \\ <<>>),
    do: bang(load(blob, perm_master, wrap_master))

  @doc """
  `load/3` for a blob stored in a file; the file is read inside the
  library.
  """
  @spec load_f(iodata(), binary(), binary()) :: {:ok, pipeline()} | {:error, reason()}
  def load_f(path, perm_master \\ <<>>, wrap_master \\ <<>>),
    do: :itb.load_f(path, perm_master, wrap_master)

  @doc "As `load_f/3`, unwrapping the pipeline or raising `ITB.Error`."
  @spec load_f!(iodata(), binary(), binary()) :: pipeline()
  def load_f!(path, perm_master \\ <<>>, wrap_master \\ <<>>),
    do: bang(load_f(path, perm_master, wrap_master))

  @doc """
  The current serialised session blob — the bytes `init/2` produced,
  the bytes `load/3` re-marshalled, or the bytes of the latest
  `rekey/3`.
  """
  @spec save(pipeline()) :: {:ok, binary()} | {:error, reason()}
  def save(pipeline), do: :itb.save(pipeline)

  @doc "As `save/1`, unwrapping the binary or raising `ITB.Error`."
  @spec save!(pipeline()) :: binary()
  def save!(pipeline), do: bang(save(pipeline))

  @doc """
  Writes the current session blob to `path` inside the library (mode
  `0600`; the containing directory must exist).
  """
  @spec save_f(pipeline(), iodata()) :: :ok | {:error, reason()}
  def save_f(pipeline, path), do: :itb.save_f(pipeline, path)

  @doc "As `save_f/2`, returning `:ok` or raising `ITB.Error`."
  @spec save_f!(pipeline(), iodata()) :: :ok
  def save_f!(pipeline, path), do: bang(save_f(pipeline, path))

  @doc """
  Sets the worker cap for every subsequent cipher call. `n` is
  clamped, never rejected: `n <= 0` selects auto, `1..256` pins the
  cap, larger values are treated as 256. The cap is per-machine
  tuning and is never written to the blob.
  """
  @spec max_workers(pipeline(), integer()) :: :ok | {:error, reason()}
  def max_workers(pipeline, n), do: :itb.max_workers(pipeline, n)

  @doc """
  Rotates the parallax + wrapper masters and returns the refreshed
  session blob (also observable through `save/1`). Must not run
  concurrently with cipher calls or open stream sessions on the same
  Pipeline.
  """
  @spec rekey(pipeline(), binary(), binary()) :: {:ok, binary()} | {:error, reason()}
  def rekey(pipeline, perm_master, wrap_master),
    do: :itb.rekey(pipeline, perm_master, wrap_master)

  @doc "As `rekey/3`, unwrapping the refreshed blob or raising `ITB.Error`."
  @spec rekey!(pipeline(), binary(), binary()) :: binary()
  def rekey!(pipeline, perm_master, wrap_master),
    do: bang(rekey(pipeline, perm_master, wrap_master))

  @doc """
  Eagerly closes (zeroing key material Go-side) and releases the
  handle. Idempotent; subsequent calls on the handle fail with
  `{:error, {:bad_handle, _}}`. Garbage collection of the last term
  reference is the release backstop.
  """
  @spec free(pipeline()) :: :ok
  def free(pipeline), do: :itb.free(pipeline)

  # ------------------------------------------------------------------
  # Single Message encrypt / decrypt
  # ------------------------------------------------------------------

  @doc "One call, one self-contained wire."
  @spec encrypt_message(pipeline(), iodata()) :: {:ok, binary()} | {:error, reason()}
  def encrypt_message(pipeline, plain), do: :itb.encrypt_message(pipeline, plain)

  @doc "As `encrypt_message/2`, unwrapping the wire or raising `ITB.Error`."
  @spec encrypt_message!(pipeline(), iodata()) :: binary()
  def encrypt_message!(pipeline, plain), do: bang(encrypt_message(pipeline, plain))

  @doc "Receive-side counterpart of `encrypt_message/2`."
  @spec decrypt_message(pipeline(), iodata()) :: {:ok, binary()} | {:error, reason()}
  def decrypt_message(pipeline, wire), do: :itb.decrypt_message(pipeline, wire)

  @doc "As `decrypt_message/2`, unwrapping the plaintext or raising `ITB.Error`."
  @spec decrypt_message!(pipeline(), iodata()) :: binary()
  def decrypt_message!(pipeline, wire), do: bang(decrypt_message(pipeline, wire))

  # ------------------------------------------------------------------
  # One-shot stream encrypt / decrypt
  # ------------------------------------------------------------------

  @doc """
  One-shot stream encrypt for callers holding the whole plaintext in
  memory: a single call through the Pipeline's stream chain. For
  bounded-memory streaming use the lazy `stream_encrypt/3` adapter or
  the incremental `encrypt_stream/1` session.
  """
  @spec encrypt_stream_one_shot(pipeline(), iodata()) ::
          {:ok, binary()} | {:error, reason()}
  def encrypt_stream_one_shot(pipeline, plain),
    do: :itb.encrypt_stream_one_shot(pipeline, plain)

  @doc "As `encrypt_stream_one_shot/2`, unwrapping the wire or raising `ITB.Error`."
  @spec encrypt_stream_one_shot!(pipeline(), iodata()) :: binary()
  def encrypt_stream_one_shot!(pipeline, plain),
    do: bang(encrypt_stream_one_shot(pipeline, plain))

  @doc "Receive-side counterpart of `encrypt_stream_one_shot/2`."
  @spec decrypt_stream_one_shot(pipeline(), iodata()) ::
          {:ok, binary()} | {:error, reason()}
  def decrypt_stream_one_shot(pipeline, wire),
    do: :itb.decrypt_stream_one_shot(pipeline, wire)

  @doc "As `decrypt_stream_one_shot/2`, unwrapping the plaintext or raising `ITB.Error`."
  @spec decrypt_stream_one_shot!(pipeline(), iodata()) :: binary()
  def decrypt_stream_one_shot!(pipeline, wire),
    do: bang(decrypt_stream_one_shot(pipeline, wire))

  # ------------------------------------------------------------------
  # Incremental stream sessions
  # ------------------------------------------------------------------

  @doc """
  Opens an incremental encrypt session (plaintext in, wire out). The
  session must not outlive its Pipeline (it pins the pipeline term,
  so dropping the pipeline reference alone never frees it early).
  """
  @spec encrypt_stream(pipeline()) :: {:ok, stream()} | {:error, reason()}
  def encrypt_stream(pipeline), do: :itb.encrypt_stream(pipeline)

  @doc "As `encrypt_stream/1`, unwrapping the session or raising `ITB.Error`."
  @spec encrypt_stream!(pipeline()) :: stream()
  def encrypt_stream!(pipeline), do: bang(encrypt_stream(pipeline))

  @doc "Receive-side counterpart (wire in, plaintext out)."
  @spec decrypt_stream(pipeline()) :: {:ok, stream()} | {:error, reason()}
  def decrypt_stream(pipeline), do: :itb.decrypt_stream(pipeline)

  @doc "As `decrypt_stream/1`, unwrapping the session or raising `ITB.Error`."
  @spec decrypt_stream!(pipeline()) :: stream()
  def decrypt_stream!(pipeline), do: bang(decrypt_stream(pipeline))

  @doc """
  Feeds data into the session. Blocks (on a dirty scheduler) until
  the cipher chain accepts the bytes; errors are sticky.
  """
  @spec stream_write(stream(), iodata()) :: :ok | {:error, reason()}
  def stream_write(stream, data), do: :itb.stream_write(stream, data)

  @doc "As `stream_write/2`, returning `:ok` or raising `ITB.Error`."
  @spec stream_write!(stream(), iodata()) :: :ok
  def stream_write!(stream, data), do: bang(stream_write(stream, data))

  @doc """
  Signals end-of-input. Idempotent; a write after end fails with
  `{:error, {:bad_input, _}}`.
  """
  @spec stream_end(stream()) :: :ok | {:error, reason()}
  def stream_end(stream), do: :itb.stream_end(stream)

  @doc "As `stream_end/1`, returning `:ok` or raising `ITB.Error`."
  @spec stream_end!(stream()) :: :ok
  def stream_end!(stream), do: bang(stream_end(stream))

  @doc """
  Drains up to `max_bytes` produced bytes (default 1 MiB). Returns
  `{:ok, data, finished}` — `data` may be `<<>>` when nothing is
  currently available, and `finished` is `true` once the session has
  ended AND the output is fully drained. Partial drains are the
  normal mode. After `stream_end/1`, an empty-spool read blocks
  until the terminal bytes arrive or the session errors.
  """
  @spec stream_read(stream(), pos_integer()) ::
          {:ok, binary(), boolean()} | {:error, reason()}
  def stream_read(stream, max_bytes \\ @read_buf), do: :itb.stream_read(stream, max_bytes)

  @doc "As `stream_read/2`, returning `{data, finished}` or raising `ITB.Error`."
  @spec stream_read!(stream(), pos_integer()) :: {binary(), boolean()}
  def stream_read!(stream, max_bytes \\ @read_buf), do: bang(stream_read(stream, max_bytes))

  @doc """
  Cancels (if still running) and eagerly releases the session. Safe
  from any state — mid-flight, mid-error, or after a clean drain.
  Idempotent; garbage collection is the release backstop.
  """
  @spec stream_free(stream()) :: :ok
  def stream_free(stream), do: :itb.stream_free(stream)

  # ------------------------------------------------------------------
  # Lazy Stream adapters
  # ------------------------------------------------------------------

  @doc """
  Lazily encrypts an enumerable of plaintext chunks through one
  incremental session, returning an Elixir `Stream` of wire
  binaries. See `ITB.Stream.encrypt/3`.
  """
  @spec stream_encrypt(pipeline(), Enumerable.t(), keyword()) :: Enumerable.t()
  def stream_encrypt(pipeline, enumerable, opts \\ []),
    do: ITB.Stream.encrypt(pipeline, enumerable, opts)

  @doc """
  Lazily decrypts an enumerable of wire chunks through one
  incremental session, returning an Elixir `Stream` of plaintext
  binaries. See `ITB.Stream.decrypt/3`.
  """
  @spec stream_decrypt(pipeline(), Enumerable.t(), keyword()) :: Enumerable.t()
  def stream_decrypt(pipeline, enumerable, opts \\ []),
    do: ITB.Stream.decrypt(pipeline, enumerable, opts)

  # ------------------------------------------------------------------
  # Profile catalogue
  # ------------------------------------------------------------------

  @doc """
  Decodes the blob's embedded profile record without opening a
  Pipeline. No registry read, no primitive probe.
  """
  @spec inspect(binary()) :: {:ok, profile()} | {:error, reason()}
  def inspect(blob), do: :itb.inspect(blob)

  @doc "As `inspect/1`, unwrapping the record or raising `ITB.Error`."
  @spec inspect!(binary()) :: profile()
  def inspect!(blob), do: bang(inspect(blob))

  @doc """
  Registers a profile record under `name` so subsequent `init/2` /
  `lookup/1` calls resolve it. `profile` is the record as a map (the
  shape `inspect/1` / `lookup/1` return) or an already-encoded JSON
  binary; a `"name"` key inside it, if present, must be empty or
  equal to `name`. Validation is performed by libitb; a duplicate
  name fails with `{:error, {:profile_exists, _}}`.
  """
  @spec register(iodata() | atom(), profile() | iodata()) :: :ok | {:error, reason()}
  def register(name, profile), do: :itb.register(name, profile)

  @doc "As `register/2`, returning `:ok` or raising `ITB.Error`."
  @spec register!(iodata() | atom(), profile() | iodata()) :: :ok
  def register!(name, profile), do: bang(register(name, profile))

  @doc """
  The profile record registered under `name` (a shipped catalogue
  entry or a prior `register/2`). An unknown name fails with
  `{:error, {:unknown_profile, _}}`.
  """
  @spec lookup(iodata() | atom()) :: {:ok, profile()} | {:error, reason()}
  def lookup(name), do: :itb.lookup(name)

  @doc "As `lookup/1`, unwrapping the record or raising `ITB.Error`."
  @spec lookup!(iodata() | atom()) :: profile()
  def lookup!(name), do: bang(lookup(name))

  @doc "The sorted list of every registered profile name."
  @spec profiles() :: [binary()]
  def profiles, do: :itb.profiles()

  # ------------------------------------------------------------------
  # Runtime + diagnostics
  # ------------------------------------------------------------------

  @doc ~S(The libitb library version string, e.g. `"0.4.1"`.)
  @spec version() :: {:ok, binary()} | {:error, reason()}
  def version, do: :itb.version()

  @doc "As `version/0`, unwrapping the binary or raising `ITB.Error`."
  @spec version!() :: binary()
  def version!, do: bang(version())

  @doc """
  The Go-side diagnostic recorded by the most recent failing libitb
  call (process-global last-write-wins; `<<>>` when none). The error
  tuples already carry this detail — direct use is for ad-hoc
  debugging only.
  """
  @spec last_error() :: binary()
  def last_error, do: :itb.last_error()

  @doc """
  Sets the Go runtime's soft heap limit in bytes; returns the
  previous limit. A negative value queries without changing.
  """
  @spec set_memory_limit(integer()) :: integer()
  def set_memory_limit(bytes), do: :itb.set_memory_limit(bytes)

  @doc """
  Sets the Go GC trigger percentage; returns the previous value. A
  negative value queries without changing.
  """
  @spec set_gc_percent(integer()) :: integer()
  def set_gc_percent(pct), do: :itb.set_gc_percent(pct)

  # ------------------------------------------------------------------
  # Result unwrapping for the bang variants
  # ------------------------------------------------------------------

  defp bang(:ok), do: :ok
  defp bang({:ok, value}), do: value
  defp bang({:ok, data, finished}), do: {data, finished}
  defp bang({:error, reason}), do: raise(ITB.Error, reason)
end
