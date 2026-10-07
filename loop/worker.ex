defmodule Loop.Worker do
  @moduledoc """
  The worker: its process body (one warmup iteration, the warmup
  barrier, the main loop), one iteration, the session pump loop the
  stream shape drives, and the round-trip comparison that decides
  between a worker error and a data mismatch.
  """

  alias Loop.{Config, Payload, Run, Size, State, WStats}

  # Largest slice fed to a stream session per write; the drain after
  # every write uses the same bound.
  @pump_slice 1024 * 1024

  defmodule W do
    @moduledoc "One worker's private state."
    defstruct [:id, :run, plaintext: <<>>, payload_mode: :fixed, seeded: false, rng: 0,
               iters: 0, bytes_enc: 0, bytes_dec: 0, nanos_enc: 0, nanos_dec: 0,
               failed: false, error: ""]
  end

  @spec shape_name(atom()) :: String.t()
  def shape_name(:stream), do: "stream"
  def shape_name(:message), do: "message"
  def shape_name(:stream_one_shot), do: "stream_one_shot"
  def shape_name(:both), do: "both"

  @spec parse_shape(String.t()) :: {:ok, atom()} | :error
  def parse_shape("stream"), do: {:ok, :stream}
  def parse_shape("message"), do: {:ok, :message}
  def parse_shape("stream_one_shot"), do: {:ok, :stream_one_shot}
  def parse_shape("both"), do: {:ok, :both}
  def parse_shape(_), do: :error

  @doc """
  Concurrency mode. This binding runs shared-handle: BEAM processes
  call the NIF beneath the Elixir wrapper concurrently on dirty
  schedulers, and one Pipeline handle serves all of them, which the
  shared library permits after construction. `--goroutines` is
  therefore the process count verbatim and is never clamped. The
  handles are not captured here: every iteration receives them with
  its read-lock grant, because a blob reopen replaces them mid-run.
  """
  @spec start(%Run{}, non_neg_integer(), binary(), pid()) :: pid()
  def start(%Run{cfg: %Config{} = cfg} = run, id, plaintext, parent) do
    w = %W{
      id: id,
      run: run,
      plaintext: plaintext,
      payload_mode: cfg.payload_mode,
      seeded: cfg.seed != 0,
      rng: Payload.seed_worker(cfg.seed, id)
    }

    spawn(fn -> body(w, parent) end)
  end

  # The worker process body: one warmup iteration, the warmup barrier,
  # then the main loop until a stop is requested or the fixed
  # per-worker iteration budget (warmup included) is spent. A failing
  # warmup still passes both barriers so the launcher never waits on a
  # worker that has already given up.
  defp body(w0, parent) do
    # Warmup iteration — counted in the totals; its completion feeds
    # the post-warmup baselines.
    w1 = iterate(w0, 0)
    send(parent, {:warmup_done, self()})

    receive do
      :release -> :ok
    end

    w2 = if w1.failed, do: w1, else: main_loop(w1, 1)
    send(parent, {:worker_done, self(), stats(w2, Size.now_ns())})
  end

  defp main_loop(w, iter) do
    cfg = w.run.cfg
    budget = cfg.iterations

    if (budget > 0 and iter >= budget) or State.stop_requested?(w.run.flags) do
      w
    else
      w1 = iterate(w, iter)

      cond do
        w1.failed ->
          w1

        true ->
          case Loop.Ops.maintenance(w.run, w1.id, iter) do
            :ok -> main_loop(w1, iter + 1)
            {:error, text} -> fail(w1, text)
          end
      end
    end
  end

  defp stats(w, finish_ns) do
    %WStats{
      id: w.id,
      iters: w.iters,
      bytes_enc: w.bytes_enc,
      bytes_dec: w.bytes_dec,
      nanos_enc: w.nanos_enc,
      nanos_dec: w.nanos_dec,
      finish_ns: finish_ns,
      failed: w.failed,
      error: w.error
    }
  end

  # Records the worker's error text (first error wins) and requests a
  # stop of the whole run.
  defp fail(w, text) do
    State.request_stop(w.run.flags)
    if w.failed, do: w, else: %{w | failed: true, error: text}
  end

  # ------------------------------------------------------------------
  # One iteration
  # ------------------------------------------------------------------

  # One iteration. In order: refill the plaintext under rotating mode;
  # take the read lock; pick the surface; encrypt (timed); decrypt
  # (timed); compare the round-trip with the plaintext; bump the
  # counters; release the lock. The whole round-trip runs under the read
  # lock so handle-mutating maintenance (rekey, blob reopen) never lands
  # between an encrypt and its matching decrypt — maintenance runs after
  # this returns, from the worker loop. The handles arrive with the
  # grant rather than from the worker's own state, because a blob reopen
  # swaps them.
  defp iterate(w0, iter) do
    w = refill(w0)

    if w.failed do
      w
    else
      {stream_pipe, msg_pipe} = State.read_lock(w.run.state)

      try do
        case round_trip(w, iter, stream_pipe, msg_pipe) do
          {:ok, w1} -> w1
          {:error, text} -> fail(w, text)
        end
      after
        State.read_unlock(w.run.state)
      end
    end
  end

  defp refill(%W{payload_mode: :rotating} = w) do
    {buf, rng} = Payload.fill(:rotating, w.seeded, w.rng, byte_size(w.plaintext))
    %{w | plaintext: buf, rng: rng}
  end

  defp refill(w), do: w

  defp round_trip(w, iter, stream_pipe, msg_pipe) do
    shape = select_shape(w.run.cfg, iter)
    plain = w.plaintext

    case encrypt(shape, stream_pipe, msg_pipe, plain) do
      {:error, what, status, detail} ->
        {:error, cipher_error(w, iter, shape, "encrypt", what, status, detail)}

      {:ok, wire, enc_ns} ->
        case decrypt(shape, stream_pipe, msg_pipe, wire) do
          {:error, what, status, detail} ->
            {:error, cipher_error(w, iter, shape, "decrypt", what, status, detail)}

          {:ok, got, dec_ns} ->
            compare(w, iter, shape, plain, got)

            {:ok,
             %{
               w
               | iters: w.iters + 1,
                 bytes_enc: w.bytes_enc + byte_size(plain),
                 bytes_dec: w.bytes_dec + byte_size(got),
                 nanos_enc: w.nanos_enc + enc_ns,
                 nanos_dec: w.nanos_dec + dec_ns
             }}
        end
    end
  end

  # Shape dispatch. `message` is one whole-buffer call on the Single
  # Message Pipeline; `stream_one_shot` is one whole-buffer call on the
  # streaming Pipeline (the C ABI's `ITB_Triple_EncryptStream`, which
  # routes to the same one-shot stream entry the Go harness calls by
  # name); `stream` opens a session on the same streaming Pipeline and
  # drives the chunk loop from here. Under `both` the three rotate by
  # iteration number so the session path and the whole-buffer path
  # alternate on one handle inside every worker — the cross-path
  # state-reuse hazard this harness exists to catch.
  defp select_shape(%Config{shape: :both}, iter) do
    case rem(iter, 3) do
      0 -> :stream
      1 -> :message
      _ -> :stream_one_shot
    end
  end

  defp select_shape(%Config{shape: shape}, _iter), do: shape

  defp encrypt(:stream, stream_pipe, _msg, plain),
    do: timed(fn -> pump(stream_pipe, :encrypt, plain) end)

  defp encrypt(:stream_one_shot, stream_pipe, _msg, plain),
    do: timed(fn -> one_call(ITB.encrypt_stream_one_shot(stream_pipe, plain)) end)

  defp encrypt(:message, _stream, msg_pipe, plain),
    do: timed(fn -> one_call(ITB.encrypt_message(msg_pipe, plain)) end)

  defp decrypt(:stream, stream_pipe, _msg, wire),
    do: timed(fn -> pump(stream_pipe, :decrypt, wire) end)

  defp decrypt(:stream_one_shot, stream_pipe, _msg, wire),
    do: timed(fn -> one_call(ITB.decrypt_stream_one_shot(stream_pipe, wire)) end)

  defp decrypt(:message, _stream, msg_pipe, wire),
    do: timed(fn -> one_call(ITB.decrypt_message(msg_pipe, wire)) end)

  defp timed(fun) do
    t0 = Size.now_ns()

    case fun.() do
      {:ok, out} -> {:ok, out, Size.now_ns() - t0}
      error -> error
    end
  end

  # A whole-buffer call names itself as the failing call, so the error
  # text carries the direction once rather than twice.
  defp one_call({:ok, out}), do: {:ok, out}
  defp one_call({:error, {status, detail}}), do: {:error, :same, status, detail}

  # ------------------------------------------------------------------
  # Stream pump
  # ------------------------------------------------------------------

  # Pump loop. The Go harness hands ITB an `io.Reader` / `io.Writer`
  # pair and ITB drives the chunk loop internally; the binding's session
  # surface has no reader / writer entry, so the caller drives it: open
  # a session, feed slices of at most 1 MiB, drain whatever the session
  # has produced after every write (a read before end never blocks),
  # end, then drain until the session reports finished (after end, a
  # read on an empty spool blocks until the terminal bytes arrive). The
  # loop is written here rather than delegated to the binding's lazy
  # stream convenience so it stands in the utility, at the same place,
  # in every language.
  defp pump(pipe, direction, src) do
    begin =
      case direction do
        :encrypt -> ITB.encrypt_stream(pipe)
        :decrypt -> ITB.decrypt_stream(pipe)
      end

    case begin do
      {:error, {status, detail}} ->
        {:error, "StreamBegin", status, detail}

      {:ok, session} ->
        result = feed(session, src, [])
        ITB.stream_free(session)
        result
    end
  end

  defp feed(session, <<>>, acc) do
    case ITB.stream_end(session) do
      {:error, {status, detail}} -> {:error, "StreamEnd", status, detail}
      :ok -> drain_final(session, acc)
    end
  end

  defp feed(session, src, acc) do
    n = min(byte_size(src), @pump_slice)
    <<slice::binary-size(^n), rest::binary>> = src

    case ITB.stream_write(session, slice) do
      {:error, {status, detail}} ->
        {:error, "StreamWrite", status, detail}

      :ok ->
        case drain_ready(session, acc) do
          {:error, _, _, _} = err -> err
          {:ok, acc1} -> feed(session, rest, acc1)
        end
    end
  end

  defp drain_ready(session, acc) do
    case ITB.stream_read(session, @pump_slice) do
      {:error, {status, detail}} -> {:error, "StreamRead", status, detail}
      {:ok, <<>>, _finished} -> {:ok, acc}
      {:ok, data, _finished} -> drain_ready(session, [data | acc])
    end
  end

  defp drain_final(session, acc) do
    case ITB.stream_read(session, @pump_slice) do
      {:error, {status, detail}} ->
        {:error, "StreamRead", status, detail}

      {:ok, data, true} ->
        {:ok, [data | acc] |> Enum.reverse() |> IO.iodata_to_binary()}

      {:ok, data, false} ->
        drain_final(session, [data | acc])
    end
  end

  # ------------------------------------------------------------------
  # Failure model
  # ------------------------------------------------------------------

  # Failure model. A cipher call that returns a non-OK status is a
  # worker error: it is recorded, the run is asked to stop, the other
  # workers finish their in-flight iteration, and the error is listed in
  # the summary with the FAIL verdict. A round-trip that returns OK with
  # different bytes is a data mismatch: the process terminates here,
  # without summary or cleanup, because the Pipeline state that produced
  # the wrong bytes is the evidence and nothing that runs afterwards may
  # touch it.
  defp compare(_w, _iter, _shape, plain, plain), do: :ok

  defp compare(w, iter, shape, plain, got) do
    off = :binary.longest_common_prefix([plain, got])

    Loop.Main.emit(:stderr, [
      "loop: DATA MISMATCH g#{w.id} iter #{iter} shape=#{shape_name(shape)}: ",
      "want #{byte_size(plain)} bytes, got #{byte_size(got)} bytes, ",
      "first difference at offset #{off}: ",
      "want #{hex_window(plain, off)} got #{hex_window(got, off)}\n"
    ])

    :erlang.halt(3, flush: true)
  end

  # Up to 16 bytes from `off` as lowercase hex, or "-" when the buffer
  # has no bytes there.
  defp hex_window(bin, off) when off >= byte_size(bin), do: "-"

  defp hex_window(bin, off) do
    n = min(16, byte_size(bin) - off)
    Base.encode16(binary_part(bin, off, n), case: :lower)
  end

  defp cipher_error(w, iter, shape, direction, :same, status, detail) do
    "g#{w.id} iter #{iter} shape=#{shape_name(shape)}: #{direction}: " <>
      Loop.Main.status_text(status, detail)
  end

  defp cipher_error(w, iter, shape, direction, what, status, detail) do
    "g#{w.id} iter #{iter} shape=#{shape_name(shape)}: #{direction}: #{what}: " <>
      Loop.Main.status_text(status, detail)
  end
end
