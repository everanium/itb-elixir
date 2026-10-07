defmodule Loop.Main do
  @moduledoc """
  Long-run stress harness. The loop utility holds one Pipeline handle
  per exercised cipher surface for minutes, hammers it with concurrent
  encrypt -> decrypt -> compare round-trips from N worker processes,
  rotates the outer masters and reopens the handle from its session
  blob on a schedule, and reports whether the process survived with
  every byte intact. It is the Elixir binding's counterpart of the Go
  harness under `tools/loop`: the same flags, the same round
  structure, the same summary in both renderings.

  The default shape is full production: the Streaming AEAD profile
  with parallax on, wrapper on, hmac-blake3 MAC, Areion-SoEM-512 inner
  hash, 1024-bit keys, and the compile-in 512-bit nonce width, driven
  through a stream session by three workers for five minutes on 16 MiB
  plaintexts. Every worker owns a distinct CSPRNG-generated plaintext
  held for the whole run, so any cross-call state leakage inside the
  Pipeline surfaces as a data mismatch between workers rather than
  cancelling out.

  A failure is one of two things. A cipher, rekey or load call that
  returns a non-OK status is a worker error: the run stops, the
  summary lists it, the verdict is FAIL and the exit code 1. A
  round-trip that returns without error but with different bytes is a
  data mismatch: the process terminates on the spot with exit code 3,
  printing the worker, the iteration and the first differing offset,
  and no summary — the state that produced the wrong bytes is the
  evidence. A crash inside the shared library or the emulator has no
  exit code of its own here; surfacing it is what the utility is for.

  Usage:

      ./loop --duration 5m --goroutines 3 --shape stream --hash areion512 \\
             --mac hmac-blake3 --payload-size 16MB --memlimit auto \\
             --parallax on --wrapper on

  Ctrl-C triggers a graceful shutdown: in-flight iterations complete,
  then the partial summary prints.
  """

  @behaviour :gen_event

  alias Loop.{Config, Payload, Run, Size, State, Summary, Worker, WStats}

  @max_workers 10
  @concurrency "shared-handle"
  @default_stream_profile "streaming-aead-triple-mac-v1"
  @default_message_profile "singlemsg-triple-mac-v1"

  # The primitive supplied for the parallax palette and the outer
  # cipher when a profile leaves them unnamed.
  @keystream_fill_cipher "aescmac"

  # ------------------------------------------------------------------
  # Logging
  # ------------------------------------------------------------------

  @doc """
  Prints one prefixed status line to stdout.

  Elixir-specific. The line and its newline are handed to the io
  server as one request: workers log concurrently during maintenance,
  and a routine that emitted the text and the newline as two requests
  would let another worker's line land between them.
  """
  @spec log(iodata()) :: :ok
  def log(text), do: emit(:stdio, ["[loop] ", text, "\n"])

  defp err(text), do: emit(:stderr, ["loop: ", text, "\n"])

  @doc """
  Writes `data` to `device` as one request, and ends the process when
  the device is gone. Every write of this utility goes through here.

  Elixir-specific. The emulator ignores SIGPIPE, so a consumer that
  stops reading does not end the run the way it ends the reference:
  the io server behind the closed descriptor exits, the write raises,
  and the node would halt on its own terms with exit 1. The failed
  write is answered with the exit code the signal would have produced,
  141, with nothing further printed and nothing flushed.
  """
  @spec emit(atom() | pid(), iodata()) :: :ok
  def emit(device, data) do
    IO.write(device, data)
  catch
    _kind, _reason -> :erlang.halt(141, flush: false)
  end

  # Keeps the emulator's own report about the closed pipe off stderr.
  #
  # Elixir-specific. When stdout is a closed pipe the emulator's stdout
  # writer dies of epipe, and the terminal driver files an error report
  # about it before it stops; only then does the io server go away and
  # the failed write above end the process. The report therefore leaves
  # the driver ahead of the halt, and whether the default handler gets
  # it onto stderr first is a race the utility cannot win from the
  # failing write. The primary filter installed at start runs inside
  # the driver before the report reaches any handler and drops that one
  # report — the stdout writer, reason epipe — and no other, so every
  # other event the emulator files still prints.
  defp install_closed_pipe_filter do
    :ok =
      :logger.add_primary_filter(
        :loop_closed_pipe,
        {&__MODULE__.closed_pipe_filter/2, nil}
      )
  end

  @doc false
  @spec closed_pipe_filter(:logger.log_event(), term()) :: :stop | :ignore
  def closed_pipe_filter(
        %{msg: {format, [:epipe]}, meta: %{mfa: {:user_drv, _, _}}},
        _
      ) do
    case :string.prefix(format, "Writer crashed") do
      :nomatch -> :ignore
      _ -> :stop
    end
  end

  def closed_pipe_filter(_event, _), do: :ignore

  @spec on_off(boolean()) :: String.t()
  def on_off(true), do: "on"
  def on_off(false), do: "off"

  @doc """
  `status <code>: <sentence>` — the numeric code the binding resolves
  from the status the failing call returned, and the diagnostic that
  call left behind, with nothing composed on this side of the
  boundary. The sentence is taken whole however long it is: the
  binding hands it over as a value the runtime owns, so no buffer
  bounds it here.
  """
  @spec status_text(atom(), binary()) :: String.t()
  def status_text(status, detail), do: "status #{ITB.Status.code(status)}: #{detail}"

  @doc """
  Renders an encoder policy env value for the summary: the raw string
  when set, `default` when the shipped ladder applies.
  """
  @spec policy_label(String.t()) :: String.t()
  def policy_label(name) do
    case System.get_env(name) do
      nil ->
        "default"

      value ->
        case String.trim_leading(value, " ") |> String.trim_leading("\t") do
          "" -> "default"
          trimmed -> trimmed
        end
    end
  end

  # ------------------------------------------------------------------
  # Flags
  # ------------------------------------------------------------------

  # One command-line flag: its name, the type label the usage prints,
  # the kind that governs parsing and the default suffix, and its help
  # text. Values are validated after the whole line is parsed. The
  # table is in alphabetical order, the order the usage prints.
  @flags [
    {"barrier-fill", "int", :int,
     "DRBG barrier fill margin: 1 | 2 | 4 | 8 | 16 | 32; 0 = profile default (1)"},
    {"blob-cycle-every", "int", :int64,
     "reopen each pipeline from its session blob every N iterations per worker; 0 = never"},
    {"blob-mode", "int", :int,
     "container floor sizing mode: 1 (per-region, default) | 2 (per-container)"},
    {"chunk-size", "string", :string,
     "streaming chunk-size budget (e.g. 4MB); 0 = profile default; inert for pure message shape"},
    {"drbg", "string", :string,
     "DRBG fill primitive name (see itb3 drbgs); empty = profile default (auto tier)"},
    {"duration", "duration", :string,
     "run duration (Go format: 30s / 5m / 1h); ignored when --iterations > 0"},
    {"gogc", "int", :int, "GC trigger percentage; 0 = leave the runtime default"},
    {"gomaxprocs", "int", :int,
     "Go runtime GOMAXPROCS override; 0 = inherit from the environment"},
    {"goroutines", "int", :int,
     "concurrent workers (1..10); on runtimes without parallelism values above 1 are clamped to 1"},
    {"hash", "string", :string, "inner ITB hash primitive name"},
    {"iterations", "int", :int64, "fixed per-worker iteration count; 0 = duration-based"},
    {"json-output", "", :bool,
     "print the final summary as one compact JSON object instead of log lines"},
    {"key-bits", "int", :int,
     "per-seed key width in bits: 512 | 1024 | 2048; 0 = profile default (1024)"},
    {"mac", "string", :string, "MAC primitive name"},
    {"memlimit", "string", :string,
     "Go heap soft limit: auto (1GiB when goroutines <= 3, else 256MiB, applied only when the runtime has no limit) or a size (e.g. 512MB)"},
    {"memprofile", "string", :string,
     "write a Go runtime heap profile (pprof) to this path at the end of the run; empty = none"},
    {"nonce-bits", "int", :int,
     "on-wire nonce width in bits: 128 | 256 | 512; 0 = profile default (512)"},
    {"parallax", "string", :string, "parallax layer: on | off"},
    {"payload-mode", "string", :string,
     "plaintext content: fixed | rotating | pattern-zero | pattern-ff | pattern-ascii"},
    {"payload-size", "string", :string,
     "per-iteration plaintext size (e.g. 1MB / 16MB / 64MB)"},
    {"profile", "string", :string,
     "exercise this single registered triple profile (overrides --shape with the profile's surface); empty = shape-based profile pair"},
    {"rekey-every", "int", :int64,
     "rotate the parallax + wrapper masters via Rekey every N iterations per worker; 0 = never"},
    {"seed", "uint", :uint64,
     "deterministic plaintext RNG seed for bug reproduction, NOT for security testing (pipeline keys stay CSPRNG-drawn); 0 = crypto/rand plaintexts"},
    {"shape", "string", :string,
     "cipher surface to exercise: stream | message | stream_one_shot | both"},
    {"wrapper", "string", :string, "wrapper layer: on | off"}
  ]

  @defaults %{
    "barrier-fill" => 0,
    "blob-cycle-every" => 0,
    "blob-mode" => 1,
    "chunk-size" => "0",
    "drbg" => "",
    "duration" => "5m",
    "gogc" => 0,
    "gomaxprocs" => 0,
    "goroutines" => 3,
    "hash" => "areion512",
    "iterations" => 0,
    "json-output" => false,
    "key-bits" => 0,
    "mac" => "hmac-blake3",
    "memlimit" => "auto",
    "memprofile" => "",
    "nonce-bits" => 0,
    "parallax" => "on",
    "payload-mode" => "fixed",
    "payload-size" => "16MB",
    "profile" => "",
    "rekey-every" => 0,
    "seed" => 0,
    "shape" => "stream",
    "wrapper" => "on"
  }

  defp usage do
    emit(:stderr, [
      "Usage of loop:\n"
      | Enum.map(@flags, fn {name, label, kind, help} ->
          flag_usage(name, label, kind, help, Map.fetch!(@defaults, name))
        end)
    ])
  end

  defp flag_usage(name, label, kind, help, default) do
    head = if label == "", do: ["  -", name, "\n"], else: ["  -", name, " ", label, "\n"]

    # Elixir-specific. The default-value suffix is composed by hand; a
    # flag library that appends its own renders it itself.
    suffix =
      case {kind, default} do
        {:int, 0} -> ""
        {:int, v} -> " (default #{v})"
        {:string, ""} -> ""
        {:string, v} -> " (default \"#{v}\")"
        _ -> ""
      end

    [head, "    \t", help, suffix, "\n"]
  end

  # Parses argv into the raw flag values. Accepts -name value,
  # --name value, -name=value and --name=value; a boolean flag takes
  # no value unless given as -name=true / -name=false. Returns
  # {:ok, values}, :help, or :error after printing the message.
  defp parse_argv(args), do: parse_argv(args, @defaults)

  defp parse_argv([], values), do: {:ok, values}

  defp parse_argv([arg | rest], values) do
    case arg do
      "-" <> tail when tail != "" -> parse_flag(tail, rest, values)
      _ ->
        err("unexpected positional arguments: [#{arg}]")
        :error
    end
  end

  defp parse_flag(tail, rest, values) do
    name0 = if String.starts_with?(tail, "-"), do: binary_part(tail, 1, byte_size(tail) - 1), else: tail

    case name0 do
      "h" ->
        :help

      "help" ->
        :help

      _ ->
        {name, inline} =
          case String.split(name0, "=", parts: 2) do
            [n, v] -> {n, {:value, v}}
            [n] -> {n, :none}
          end

        case List.keyfind(@flags, name, 0) do
          nil ->
            err("flag provided but not defined: -#{name}")
            usage()
            :error

          {_, _, kind, _} ->
            take_value(name, kind, inline, rest, values)
        end
    end
  end

  defp take_value(name, kind, inline, rest, values) do
    case value_of(kind, inline, rest) do
      :needs_argument ->
        err("flag needs an argument: -#{name}")
        :error

      {value, rest1} ->
        case assign(kind, value) do
          :error ->
            err("invalid value \"#{value}\" for flag -#{name}")
            :error

          {:ok, parsed} ->
            parse_argv(rest1, Map.put(values, name, parsed))
        end
    end
  end

  defp value_of(_kind, {:value, v}, rest), do: {v, rest}
  defp value_of(:bool, :none, rest), do: {"true", rest}
  defp value_of(_kind, :none, [v | rest]), do: {v, rest}
  defp value_of(_kind, :none, []), do: :needs_argument

  defp assign(:string, value), do: {:ok, value}
  defp assign(:bool, "true"), do: {:ok, true}
  defp assign(:bool, "false"), do: {:ok, false}
  defp assign(:bool, _), do: :error
  defp assign(:uint64, "-" <> _), do: :error
  defp assign(:uint64, value), do: integer_value(value)
  defp assign(:int64, value), do: integer_value(value)

  defp assign(:int, value) do
    case integer_value(value) do
      {:ok, v} when v <= 2_147_483_647 and v >= -2_147_483_647 -> {:ok, v}
      _ -> :error
    end
  end

  defp integer_value(value) do
    case Integer.parse(value) do
      {v, ""} -> {:ok, v}
      _ -> :error
    end
  end

  # ------------------------------------------------------------------
  # Validation
  # ------------------------------------------------------------------

  # Builds the resolved config from the parsed values. Returns
  # {:ok, cfg} or :error after printing "loop: <message>" for the
  # first failing rule.
  defp resolve(v) do
    with {:ok, cfg} <- resolve_duration(v),
         {:ok, cfg} <- resolve_iterations(v, cfg),
         {:ok, cfg} <- resolve_workers(v, cfg),
         {:ok, cfg} <- resolve_shape(v, cfg),
         {:ok, cfg} <- resolve_hash(v, cfg),
         {:ok, cfg} <- resolve_payload(v, cfg),
         {:ok, cfg} <- resolve_memlimit(v, cfg),
         {:ok, cfg} <- resolve_gogc(v, cfg),
         {:ok, cfg} <- resolve_layers(v, cfg),
         {:ok, cfg} <- resolve_profile(v, cfg),
         {:ok, cfg} <- resolve_key_bits(v, cfg),
         {:ok, cfg} <- resolve_nonce_bits(v, cfg),
         {:ok, cfg} <- resolve_blob_mode(v, cfg),
         {:ok, cfg} <- resolve_barrier_fill(v, cfg),
         {:ok, cfg} <- resolve_chunk_size(v, cfg),
         {:ok, cfg} <- resolve_gomaxprocs(v, cfg),
         {:ok, cfg} <- resolve_rekey(v, cfg),
         {:ok, cfg} <- resolve_blob_cycle(v, cfg),
         {:ok, cfg} <- resolve_payload_mode(v, cfg) do
      {:ok,
       %{
         cfg
         | seed: v["seed"],
           json_output: v["json-output"],
           memprofile: v["memprofile"]
       }}
    end
  end

  defp resolve_duration(v) do
    case Size.parse_duration(v["duration"]) do
      {:ok, ns} when ns > 0 -> {:ok, %Config{duration_ns: ns}}
      _ -> err("--duration must be positive, got #{v["duration"]}") && :error
    end
  end

  defp resolve_iterations(v, cfg) do
    case v["iterations"] do
      n when n < 0 -> err("--iterations must be >= 0, got #{n}") && :error
      n -> {:ok, %{cfg | iterations: n}}
    end
  end

  defp resolve_workers(v, cfg) do
    case v["goroutines"] do
      g when g < 1 or g > @max_workers ->
        err("--goroutines must be in 1..#{@max_workers}, got #{g}") && :error

      g ->
        {:ok, %{cfg | workers_requested: g, workers: g}}
    end
  end

  defp resolve_shape(v, cfg) do
    case Worker.parse_shape(v["shape"]) do
      :error ->
        err("--shape must be stream | message | stream_one_shot | both, got \"#{v["shape"]}\"") &&
          :error

      {:ok, s} ->
        {:ok, %{cfg | shape: s}}
    end
  end

  defp resolve_hash(v, cfg) do
    hash = v["hash"]

    if hash in ITB.hash_names() do
      # The MAC name is validated by Init: no registry enumeration for
      # MAC primitives crosses the boundary.
      {:ok, %{cfg | hash: hash, mac: v["mac"]}}
    else
      err("--hash \"#{hash}\" is not a registered hash primitive") && :error
    end
  end

  defp resolve_payload(v, cfg) do
    case Size.parse_size(v["payload-size"]) do
      :error -> err("--payload-size: invalid size \"#{v["payload-size"]}\"") && :error
      {:ok, n} when n < 1 -> err("--payload-size must be at least 1 byte") && :error
      {:ok, n} -> {:ok, %{cfg | payload: n}}
    end
  end

  defp resolve_memlimit(v, cfg) do
    case v["memlimit"] do
      "auto" ->
        limit = if cfg.workers <= 3, do: 1024 * 1024 * 1024, else: 256 * 1024 * 1024
        {:ok, %{cfg | memlimit_auto: true, memlimit: limit}}

      size ->
        case Size.parse_size(size) do
          :error -> err("--memlimit: invalid size \"#{size}\"") && :error
          {:ok, n} -> {:ok, %{cfg | memlimit: n}}
        end
    end
  end

  defp resolve_gogc(v, cfg) do
    case v["gogc"] do
      g when g < 0 -> err("--gogc must be >= 0, got #{g}") && :error
      g -> {:ok, %{cfg | gogc: g}}
    end
  end

  defp resolve_layers(v, cfg) do
    with {:ok, p} <- on_off_value(v["parallax"]) do
      case on_off_value(v["wrapper"]) do
        {:ok, w} -> {:ok, %{cfg | parallax: p, wrapper: w}}
        :error -> err("--wrapper must be on | off, got \"#{v["wrapper"]}\"") && :error
      end
    else
      :error -> err("--parallax must be on | off, got \"#{v["parallax"]}\"") && :error
    end
  end

  defp on_off_value("on"), do: {:ok, true}
  defp on_off_value("off"), do: {:ok, false}
  defp on_off_value(_), do: :error

  defp resolve_profile(v, cfg) do
    case v["profile"] do
      "" ->
        {:ok, cfg}

      name ->
        case profile_surface(name) do
          :error -> :error
          {:ok, surface} -> {:ok, %{cfg | profile: name, shape: narrow_shape(cfg.shape, surface)}}
        end
    end
  end

  # Resolves a registered profile to the shape family its record's
  # mode exposes by reading the record through the binding's lookup: a
  # mode beginning with "streaming" exposes the stream surfaces, one
  # beginning with "singlemsg" the message surface, "blob-only" none.
  defp profile_surface(name) do
    case ITB.lookup(name) do
      {:error, _} ->
        err("--profile \"#{name}\" is not a registered triple profile") && :error

      {:ok, record} ->
        mode = Map.get(record, "mode", "")

        cond do
          String.starts_with?(mode, "streaming") ->
            {:ok, :stream}

          String.starts_with?(mode, "singlemsg") ->
            {:ok, :message}

          true ->
            err("--profile \"#{name}\" carries no cipher surface (blob-only mode)") && :error
        end
    end
  end

  # Applies a --profile's surface to the requested shape: a
  # message-surface profile forces message; a stream-surface profile
  # keeps stream or stream_one_shot as requested and turns message or
  # both into stream.
  defp narrow_shape(_requested, :message), do: :message
  defp narrow_shape(:stream_one_shot, :stream), do: :stream_one_shot
  defp narrow_shape(_requested, :stream), do: :stream

  defp resolve_key_bits(v, cfg) do
    case v["key-bits"] do
      k when k in [0, 512, 1024, 2048] ->
        {:ok, %{cfg | key_bits: k}}

      k ->
        err("--key-bits must be 512 | 1024 | 2048 (or 0 = profile default), got #{k}") && :error
    end
  end

  defp resolve_nonce_bits(v, cfg) do
    case v["nonce-bits"] do
      n when n in [0, 128, 256, 512] ->
        {:ok, %{cfg | nonce_bits: n}}

      n ->
        err("--nonce-bits must be 128 | 256 | 512 (or 0 = profile default), got #{n}") && :error
    end
  end

  defp resolve_blob_mode(v, cfg) do
    case v["blob-mode"] do
      m when m in [1, 2] ->
        {:ok, %{cfg | blob_mode: m}}

      m ->
        err("--blob-mode must be 1 (per-region) | 2 (per-container), got #{m}") && :error
    end
  end

  defp resolve_barrier_fill(v, cfg) do
    case v["barrier-fill"] do
      b when b in [0, 1, 2, 4, 8, 16, 32] ->
        # The DRBG name is validated by Init: the C ABI enumerates no
        # DRBG names.
        {:ok, %{cfg | barrier_fill: b, drbg: v["drbg"]}}

      b ->
        err(
          "--barrier-fill must be 1 | 2 | 4 | 8 | 16 | 32 (or 0 = profile default), got #{b}"
        ) && :error
    end
  end

  defp resolve_chunk_size(v, cfg) do
    case Size.parse_size(v["chunk-size"]) do
      :error -> err("--chunk-size: invalid size \"#{v["chunk-size"]}\"") && :error
      {:ok, n} -> {:ok, %{cfg | chunk_size: n}}
    end
  end

  defp resolve_gomaxprocs(v, cfg) do
    case v["gomaxprocs"] do
      g when g < 0 -> err("--gomaxprocs must be > 0 when specified, got #{g}") && :error
      g -> {:ok, %{cfg | gomaxprocs: g}}
    end
  end

  defp resolve_rekey(v, cfg) do
    case v["rekey-every"] do
      r when r < 0 -> err("--rekey-every must be >= 0, got #{r}") && :error
      r -> {:ok, %{cfg | rekey_every: r}}
    end
  end

  defp resolve_blob_cycle(v, cfg) do
    case v["blob-cycle-every"] do
      b when b < 0 -> err("--blob-cycle-every must be >= 0, got #{b}") && :error
      b -> {:ok, %{cfg | blob_cycle_every: b}}
    end
  end

  defp resolve_payload_mode(v, cfg) do
    case Payload.parse_mode(v["payload-mode"]) do
      :error ->
        err(
          "--payload-mode must be fixed | rotating | pattern-zero | pattern-ff | pattern-ascii, got \"#{v["payload-mode"]}\""
        ) && :error

      {:ok, m} ->
        {:ok, %{cfg | payload_mode: m}}
    end
  end

  # ------------------------------------------------------------------
  # Pipelines
  # ------------------------------------------------------------------

  # Folds a keystream primitive into opts for any layer the named
  # profile leaves unfilled but the operator asked for.
  #
  # A profile built around a primitive that is safe only inside the
  # Interlocked Barrier ships with no parallax palette and no outer
  # cipher: both layers run outside the barrier, where that primitive
  # would stand bare, so the recipe leaves them unnamed rather than
  # naming a primitive that must not key them. Engaging either layer
  # therefore needs a keystream-capable primitive supplied from
  # outside the recipe; without it construction fails on a palette
  # below its minimum or an unnamed outer cipher, and the primitive
  # that most deserves stressing becomes the one that cannot be
  # stressed with those layers engaged.
  #
  # AES-CMAC is PRF-grade, so it is sound outside the Interlocked
  # Barrier, and it is the closest relative of the AES-based inner
  # primitive whose profiles need this fill. Overrides fold into the
  # resolved record the blob carries, so the receiver rebuilds the
  # same shape from the blob alone.
  defp fill_keystream_layers(name, want_parallax, want_wrapper) do
    case ITB.lookup(name) do
      {:error, _} ->
        err("--profile \"#{name}\" is not a registered triple profile") && :error

      {:ok, record} ->
        palette_opts =
          if want_parallax and not Map.has_key?(record, "palette") do
            palette = [
              {:parallaxPalette,
               Enum.map_join(1..3, ",", fn _ -> @keystream_fill_cipher end)}
            ]

            # A recipe that never carried a palette never carried a
            # segment size either, and the schedule rejects zero.
            if Map.has_key?(record, "segment"),
              do: palette,
              else: palette ++ [{:parallaxSegmentSize, "4093"}]
          else
            []
          end

        outer_opts =
          if want_wrapper and not Map.has_key?(record, "outer"),
            do: [{:outerCipher, @keystream_fill_cipher}],
            else: []

        {:ok, palette_opts ++ outer_opts}
    end
  end

  # Constructs one Pipeline against `profile` with every flag-carried
  # override in the opts list (zero values included — the shared
  # library treats zero as "profile default"), then obtains the Init
  # blob once through save: the binding's init entry does not hand the
  # blob back, and the bytes are the ones Init produced. Later blob
  # reopens use the retained blob; save is never called again.
  defp build_pipeline(%Config{} = cfg, profile) do
    base = [
      {:innerHash, cfg.hash},
      {:macName, cfg.mac},
      {:withParallax, to_string(cfg.parallax)},
      {:withWrapper, to_string(cfg.wrapper)},
      {:keyBits, Integer.to_string(cfg.key_bits)},
      {:nonceBits, Integer.to_string(cfg.nonce_bits)},
      {:barrierFill, Integer.to_string(cfg.barrier_fill)},
      {:drbg, cfg.drbg},
      {:chunkSize, Integer.to_string(cfg.chunk_size)}
    ]

    extra =
      case cfg.profile do
        "" -> {:ok, []}
        name -> fill_keystream_layers(name, cfg.parallax, cfg.wrapper)
      end

    case extra do
      :error ->
        :error

      {:ok, fill} ->
        if fill != [] do
          err(
            "#{cfg.profile} leaves the requested keystream layers unnamed; " <>
              "#{@keystream_fill_cipher} supplied for them"
          )
        end

        case ITB.init(profile, base ++ fill) do
          {:error, {status, detail}} ->
            err("Init(#{profile}): " <> status_text(status, detail)) && :error

          {:ok, pipe} ->
            case ITB.save(pipe) do
              {:error, {status, detail}} ->
                err("Save(#{profile}): " <> status_text(status, detail))
                ITB.free(pipe)
                :error

              {:ok, blob} ->
                apply_blob_mode(cfg, profile, pipe, blob)
            end
        end
    end
  end

  # The sizing mode is not an opts knob: under --blob-mode 2 the Init
  # blob is edited and the pipeline reopened from it, so the retained
  # blob (the one blob-cycle reopens from) carries the edited mode.
  defp apply_blob_mode(%Config{blob_mode: 1}, profile, pipe, blob) do
    log_pipeline_initialised(profile, blob)
    {:ok, pipe, blob}
  end

  defp apply_blob_mode(%Config{blob_mode: mode}, profile, pipe, blob) do
    ITB.free(pipe)

    case edit_inner_blob_mode(blob, mode) do
      {:error, detail} ->
        err("rewrite blob mode: #{detail}") && :error

      {:ok, edited} ->
        case ITB.load(edited) do
          {:error, {status, detail}} ->
            err("reload Mode 2 blob: " <> status_text(status, detail)) && :error

          {:ok, reloaded} ->
            log_pipeline_initialised(profile, edited)
            {:ok, reloaded, edited}
        end
    end
  end

  # Sets the inner blob's integer "mode" (1 = per-region, 2 =
  # per-container) of a session blob through the OTP json module. The
  # profile record "p" carries its own string "mode"; the target is the
  # one under "ib". Integers and strings round-trip unchanged; only the
  # key order may differ.
  defp edit_inner_blob_mode(blob, mode) do
    case :json.decode(blob) do
      %{"ib" => %{"mode" => m} = inner} = session when is_integer(m) ->
        {:ok, IO.iodata_to_binary(:json.encode(%{session | "ib" => %{inner | "mode" => mode}}))}

      _ ->
        {:error, "inner blob mode field not found"}
    end
  rescue
    e -> {:error, Exception.message(e)}
  end

  # Prints the construction line with the recipe read back from the
  # blob the Pipeline handed out, not echoed from the flags: every
  # construction override is proven to have reached the library by the
  # value the receiver would see. Record values that are empty (a No
  # MAC profile's MAC, a mixed profile's single hash) print as "-".
  defp log_pipeline_initialised(profile, blob) do
    case ITB.inspect(blob) do
      {:error, {_status, detail}} ->
        log("pipeline initialised: profile=#{profile} blob=#{byte_size(blob)} bytes (inspect: #{detail})")

      {:ok, record} ->
        log(
          "pipeline initialised: profile=#{profile} blob=#{byte_size(blob)} bytes " <>
            "hash=#{record_str(record, "hash")} key-bits=#{record_int(record, "keybits")} " <>
            "nonce-bits=#{record_int(record, "nonce_bits")} " <>
            "barrier-fill=#{record_int(record, "barrier_fill")} " <>
            "chunk-size=#{record_int(record, "chunk")} mac=#{record_str(record, "mac")} " <>
            "parallax=#{on_off(record_bool(record, "parallax"))} " <>
            "wrapper=#{on_off(record_bool(record, "wrapper"))}" <>
            if(record_int(record, "container_mode") == 2, do: " container-mode=2", else: "") <>
            case record_str(record, "drbg") do
              "-" -> ""
              drbg -> " drbg=#{drbg}"
            end
        )
    end
  end

  defp record_int(record, key) do
    case Map.get(record, key, 0) do
      v when is_integer(v) -> v
      _ -> 0
    end
  end

  defp record_str(record, key) do
    case Map.get(record, key, "") do
      "" -> "-"
      v when is_binary(v) -> v
      _ -> "-"
    end
  end

  defp record_bool(record, key), do: Map.get(record, key, false) == true

  # ------------------------------------------------------------------
  # Signals
  # ------------------------------------------------------------------

  # Graceful stop. A termination signal sets the run's stop request,
  # which every worker checks before starting an iteration, so the
  # signal interrupts nothing mid-call — the in-flight encrypt /
  # decrypt / compare completes, the worker returns, and the partial
  # summary prints with the verdict the completed iterations earned.
  # The emulator's own handler is removed first: it halts the node on
  # SIGTERM, which would end the run before the summary.
  #
  # Elixir-specific. SIGINT never reaches BEAM code: the emulator's
  # break handler owns it below the signal server, and os:set_signal/2
  # does not accept it at all. The launcher closes that gap by
  # trapping the interrupt itself and sending the emulator a
  # termination signal, which arrives here.
  defp install_signals(flags) do
    _ = :gen_event.delete_handler(:erl_signal_server, :erl_signal_handler, [])
    _ = :gen_event.add_handler(:erl_signal_server, __MODULE__, [flags])
    _ = :os.set_signal(:sigterm, :handle)
    _ = :os.set_signal(:sigquit, :handle)
    :ok
  end

  @impl :gen_event
  def init([flags]), do: {:ok, flags}

  @impl :gen_event
  def handle_event(signal, flags) when signal in [:sigterm, :sigquit] do
    State.request_stop(flags)
    {:ok, flags}
  end

  def handle_event(_signal, flags), do: {:ok, flags}

  @impl :gen_event
  def handle_call(_request, flags), do: {:ok, :ok, flags}

  @impl :gen_event
  def handle_info(_info, flags), do: {:ok, flags}

  @impl :gen_event
  def terminate(_reason, _flags), do: :ok

  # ------------------------------------------------------------------
  # Run
  # ------------------------------------------------------------------

  @spec start() :: no_return()
  def start do
    install_closed_pipe_filter()
    :erlang.halt(run(System.argv()), flush: true)
  end

  defp run(args) do
    case parse_argv(args) do
      :help ->
        usage()
        0

      :error ->
        2

      {:ok, values} ->
        case resolve(values) do
          :error -> 2
          {:ok, cfg} -> shape_runtime(cfg)
        end
    end
  end

  # Runtime shaping. A long run under allocation churn grows the Go
  # heap inside the shared library without bound unless a soft limit
  # paces the collector, so a limit is always in force: an explicit
  # --memlimit is set as given, and auto caps the heap only when the
  # runtime reports no limit at all (a limit already installed from
  # the environment is left standing). The GC percentage and GOMAXPROCS
  # are set only when their flag is non-zero — a zero flag skips the
  # setter rather than calling it with zero, because zero is a real
  # value to the GC-percent setter, and a call would clobber whatever
  # the environment installed. All of it lands before any Pipeline
  # exists so the baselines are taken under the shaped runtime.
  defp shape_runtime(%Config{} = cfg0) do
    if cfg0.memlimit_auto do
      if ITB.set_memory_limit(-1) == 0x7FFFFFFFFFFFFFFF do
        ITB.set_memory_limit(cfg0.memlimit)
      end
    else
      ITB.set_memory_limit(cfg0.memlimit)
    end

    cfg = %{cfg0 | memlimit: ITB.set_memory_limit(-1)}
    if cfg.gogc > 0, do: ITB.set_gc_percent(cfg.gogc)
    if cfg.gomaxprocs > 0, do: ITB.set_gomaxprocs(cfg.gomaxprocs)
    start_lines(cfg)
    build(cfg)
  end

  defp start_lines(%Config{} = cfg) do
    log(
      "start: duration=#{Size.human_duration(cfg.duration_ns)} iterations=#{cfg.iterations} " <>
        "goroutines=#{cfg.workers_requested} workers=#{cfg.workers} " <>
        "concurrency=#{@concurrency} shape=#{Worker.shape_name(cfg.shape)} hash=#{cfg.hash} " <>
        "mac=#{cfg.mac} payload=#{Size.human_bytes(cfg.payload)} " <>
        "memlimit=#{Size.human_bytes(cfg.memlimit)} parallax=#{on_off(cfg.parallax)} " <>
        "wrapper=#{on_off(cfg.wrapper)}"
    )

    log(
      "overrides: profile=\"#{cfg.profile}\" key-bits=#{cfg.key_bits} " <>
        "nonce-bits=#{cfg.nonce_bits} chunk-size=#{Size.human_bytes(cfg.chunk_size)} " <>
        "barrier-fill=#{cfg.barrier_fill} gomaxprocs=#{cfg.gomaxprocs} " <>
        "rekey-every=#{cfg.rekey_every} blob-cycle-every=#{cfg.blob_cycle_every} " <>
        "payload-mode=#{Payload.mode_name(cfg.payload_mode)} seed=#{cfg.seed} " <>
        "json-output=#{cfg.json_output}" <>
        if(cfg.blob_mode != 1, do: " blob-mode=#{cfg.blob_mode}", else: "") <>
        if(cfg.drbg != "", do: " drbg=#{cfg.drbg}", else: "")
    )

    log(
      "policy: microbatch-tiers=#{policy_label("ITB_MICROBATCH_TIERS")} " <>
        "hashpool-starters=#{policy_label("ITB_HASHPOOL_STARTERS")}"
    )
  end

  # Pipeline construction — one shared handle per exercised shape.
  # stream and stream_one_shot share the streaming handle.
  defp build(%Config{} = cfg) do
    stream_profile = if cfg.profile == "", do: @default_stream_profile, else: cfg.profile
    msg_profile = if cfg.profile == "", do: @default_message_profile, else: cfg.profile
    want_stream = cfg.shape in [:stream, :stream_one_shot, :both]
    want_msg = cfg.shape in [:message, :both]

    case build_optional(want_stream, cfg, stream_profile) do
      :error ->
        1

      {:ok, stream_pipe, stream_blob} ->
        case build_optional(want_msg, cfg, msg_profile) do
          :error ->
            1

          {:ok, msg_pipe, msg_blob} ->
            launch(cfg, {stream_profile, stream_pipe, stream_blob},
                   {msg_profile, msg_pipe, msg_blob})
        end
    end
  end

  defp build_optional(false, _cfg, _profile), do: {:ok, nil, <<>>}
  defp build_optional(true, cfg, profile), do: build_pipeline(cfg, profile)

  defp launch(%Config{} = cfg, {stream_profile, stream_pipe, stream_blob},
         {msg_profile, msg_pipe, msg_blob}) do
    flags = State.new_flags()
    counts = State.new_counts()
    state = State.start(stream_pipe, msg_pipe, stream_blob, msg_blob)

    run = %Run{
      cfg: cfg,
      state: state,
      flags: flags,
      counts: counts,
      stream_profile: stream_profile,
      msg_profile: msg_profile
    }

    install_signals(flags)

    # Allocation posture. Per-worker plaintexts are built once and
    # held for the whole run (rotating mode rebuilds them per
    # iteration); the pump accumulator is a per-iteration iolist the
    # collector reclaims, and the message and one-shot outputs are
    # binaries the binding returns per call. Under the default fixed
    # CSPRNG mode every worker's buffer is distinct, so cross-worker
    # data crossover is detectable; pattern modes trade that property
    # for content edge-case coverage.
    plaintexts =
      for i <- 0..(cfg.workers - 1)//1 do
        {buf, _rng} =
          Payload.fill(cfg.payload_mode, cfg.seed != 0, Payload.seed_worker(cfg.seed, i),
            cfg.payload)

        buf
      end

    # Warmup barrier. Every worker runs one iteration and waits; the
    # clock starts only once all of them have paid their first-call
    # costs (pool warm-up, lazy kernel dispatch, page faults on the
    # payload buffers), and the RSS and pool baselines taken here
    # describe a process that has already run the whole cipher path
    # once per worker.
    warmup_start = Size.now_ns()

    workers =
      for i <- 0..(cfg.workers - 1)//1 do
        pid = Worker.start(run, i, Enum.at(plaintexts, i), self())
        Process.monitor(pid)
        {pid, i}
      end

    await_warmup(workers)
    {rss_warmup, rss_peak0} = Summary.read_rss()
    pool_warmup = Summary.pool_snapshot()
    warmup_ns = Size.now_ns() - warmup_start

    log(
      "warmup: #{cfg.workers} workers x 1 iter completed in " <>
        "#{Size.human_duration(div(warmup_ns + 50_000_000, 100_000_000) * 100_000_000)} " <>
        "(baseline rss=#{Size.human_bytes(rss_warmup)})"
    )

    # Open the gate; in duration mode a timer asks the workers to stop
    # once the deadline passes.
    start_ns = Size.now_ns()
    Enum.each(workers, fn {pid, _} -> send(pid, :release) end)

    timer =
      if cfg.iterations == 0,
        do: Process.send_after(self(), :deadline, div(cfg.duration_ns, 1_000_000)),
        else: nil

    stats = collect(workers, flags, [])
    if timer, do: Process.cancel_timer(timer)

    finish_ns = Enum.max([start_ns | Enum.map(stats, & &1.finish_ns)])
    elapsed_ns = finish_ns - start_ns
    {rss_final, rss_peak} = Summary.read_rss()
    pool_steady = Summary.pool_snapshot()

    case cfg.memprofile do
      "" ->
        :ok

      path ->
        case ITB.write_heap_profile(path) do
          :ok -> log("memprofile: heap profile written to #{path}")
          {:error, {_status, detail}} -> err("memprofile: #{detail}")
        end
    end

    ordered = Enum.sort_by(stats, & &1.id)

    rc =
      Summary.final(run, ordered, elapsed_ns, {rss_warmup, max(rss_peak0, rss_peak), rss_final},
        {pool_warmup, pool_steady})

    {live_stream, live_msg} = State.handles(state)
    if live_stream, do: ITB.free(live_stream)
    if live_msg, do: ITB.free(live_msg)
    State.stop_process(state)
    rc
  end

  # Every worker reports its warmup iteration before the clock starts.
  # A worker that died instead of reporting is not waited for: the
  # monitor turns its exit into the same arrival, and the run goes on
  # to the summary that will carry the failure.
  defp await_warmup([]), do: :ok

  defp await_warmup(workers) do
    receive do
      {:warmup_done, pid} ->
        await_warmup(List.keydelete(workers, pid, 0))

      {:DOWN, _ref, :process, pid, reason} ->
        send(self(), {:worker_died, pid, reason})
        await_warmup(List.keydelete(workers, pid, 0))
    end
  end

  # Waits for every worker, turning the duration deadline into the
  # stop request the workers poll. A worker that dies without
  # reporting is recorded as a worker error so the run cannot hang on
  # it.
  defp collect([], _flags, acc), do: acc

  defp collect(workers, flags, acc) do
    receive do
      :deadline ->
        State.request_stop(flags)
        collect(workers, flags, acc)

      {:worker_done, pid, stats} ->
        flush_down(pid)
        collect(List.keydelete(workers, pid, 0), flags, [stats | acc])

      {:worker_died, pid, reason} ->
        collect_death(workers, flags, acc, pid, reason)

      {:DOWN, _ref, :process, pid, reason} ->
        collect_death(workers, flags, acc, pid, reason)
    end
  end

  defp collect_death(workers, flags, acc, pid, reason) do
    case List.keyfind(workers, pid, 0) do
      nil ->
        collect(workers, flags, acc)

      {^pid, id} ->
        State.request_stop(flags)
        collect(List.keydelete(workers, pid, 0), flags, [died(id, pid, reason) | acc])
    end
  end

  defp died(id, pid, reason) do
    %WStats{
      id: id,
      finish_ns: Size.now_ns(),
      failed: true,
      error: "g#{id} exited: #{inspect(pid)} #{inspect(reason)}"
    }
  end

  defp flush_down(pid) do
    receive do
      {:DOWN, _ref, :process, ^pid, _reason} -> :ok
    after
      0 -> :ok
    end
  end
end
