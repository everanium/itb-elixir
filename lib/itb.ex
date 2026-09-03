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
      {:ok, blob} = ITB.blob(sender)
      {:ok, receiver} = ITB.open("singlemsg-triple-mac-v1", blob)
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

  # Default drain slice for stream_read/1 (1 MiB).
  @read_buf 1_048_576

  # ------------------------------------------------------------------
  # Pipeline lifecycle
  # ------------------------------------------------------------------

  @doc """
  Constructs a fresh Pipeline against the named profile. Opts may be
  omitted for pure profile defaults.
  """
  @spec init(iodata() | atom(), opts()) :: {:ok, pipeline()} | {:error, reason()}
  def init(profile, opts \\ %{}), do: :itb.init(profile, opts)

  @doc "As `init/2`, unwrapping the pipeline or raising `ITB.Error`."
  @spec init!(iodata() | atom(), opts()) :: pipeline()
  def init!(profile, opts \\ %{}), do: bang(init(profile, opts))

  @doc """
  Reconstructs a Pipeline from a blob produced by a sender's init /
  rekey, using the blob-embedded masters.
  """
  @spec open(iodata() | atom(), binary(), opts()) :: {:ok, pipeline()} | {:error, reason()}
  def open(profile, blob, opts \\ %{}), do: :itb.open(profile, blob, opts)

  @doc """
  As `open/3` with explicit master overrides. Both masters must be
  supplied non-empty (a half-supplied pair is rejected); pass
  `<<>>` / `<<>>` for the blob-embedded masters.
  """
  @spec open(iodata() | atom(), binary(), opts(), binary(), binary()) ::
          {:ok, pipeline()} | {:error, reason()}
  def open(profile, blob, opts, perm_master, wrap_master),
    do: :itb.open(profile, blob, opts, perm_master, wrap_master)

  @doc "As `open/3`, unwrapping the pipeline or raising `ITB.Error`."
  @spec open!(iodata() | atom(), binary(), opts()) :: pipeline()
  def open!(profile, blob, opts \\ %{}), do: bang(open(profile, blob, opts))

  @doc """
  The exported session-bundle blob for the receiver side; refreshed
  by `rekey/3`.
  """
  @spec blob(pipeline()) :: {:ok, binary()} | {:error, reason()}
  def blob(pipeline), do: :itb.blob(pipeline)

  @doc "As `blob/1`, unwrapping the binary or raising `ITB.Error`."
  @spec blob!(pipeline()) :: binary()
  def blob!(pipeline), do: bang(blob(pipeline))

  @doc """
  Rotates the parallax + wrapper masters and refreshes the blob.
  Must not run concurrently with cipher calls or open stream
  sessions on the same Pipeline.
  """
  @spec rekey(pipeline(), binary(), binary()) :: :ok | {:error, reason()}
  def rekey(pipeline, perm_master, wrap_master),
    do: :itb.rekey(pipeline, perm_master, wrap_master)

  @doc "As `rekey/3`, returning `:ok` or raising `ITB.Error`."
  @spec rekey!(pipeline(), binary(), binary()) :: :ok
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
  # Profile registration
  # ------------------------------------------------------------------

  @doc """
  Registers a user-defined Triple profile under `name`; the opts
  follow the register-profile grammar validated by Go. A duplicate
  name fails with `{:error, {:profile_exists, _}}`.
  """
  @spec register_profile(iodata() | atom(), opts()) :: :ok | {:error, reason()}
  def register_profile(name, opts), do: :itb.register_profile(name, opts)

  @doc "As `register_profile/2`, returning `:ok` or raising `ITB.Error`."
  @spec register_profile!(iodata() | atom(), opts()) :: :ok
  def register_profile!(name, opts), do: bang(register_profile(name, opts))

  # ------------------------------------------------------------------
  # Runtime + diagnostics
  # ------------------------------------------------------------------

  @doc ~S(The libitb library version string, e.g. `"0.3.5"`.)
  @spec version() :: {:ok, binary()} | {:error, reason()}
  def version, do: :itb.version()

  @doc "As `version/0`, unwrapping the binary or raising `ITB.Error`."
  @spec version!() :: binary()
  def version!, do: bang(version())

  @doc """
  The shipped hash primitive roster as `[{name, width_bits}]` in
  canonical registry order.
  """
  @spec hashes() :: [{binary(), pos_integer()}]
  def hashes, do: :itb.hashes()

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
