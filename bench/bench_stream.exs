# bench_stream — stream-pump throughput vs plaintext size (Streaming
# Non-AEAD profile) at 1 MiB / 16 MiB / 64 MiB. Each iteration runs a
# full incremental session (begin -> write 1 MiB slices, draining the
# spool after each write -> end -> drain until finished -> free).
#
# Env-var overrides identical to bench_message (defaults match the
# root Go BENCH3.md pin):
#
#   ITB_PROFILE        streaming-noaead-triple-v1
#   ITB_INNER_HASH     areion512
#   ITB_KEY_BITS       1024
#   ITB_NONCE_BITS     512
#   ITB_WITH_PARALLAX  false
#   ITB_WITH_WRAPPER   false
#   ITB_BENCH_MIN_SEC  5
#
# Invocation (from bindings/elixir, after ./build.sh):
#   mix run bench/bench_stream.exs

Code.require_file("bench_util.exs", __DIR__)

defmodule BenchStream do
  import Bitwise

  @min_iters 3
  @pump_buf 1 <<< 20

  def main do
    # Bench-scale allocation churn leaks Go scratch heap unboundedly
    # without a soft memory cap + aggressive GC; the return values
    # report the previous settings, not an error.
    _ = ITB.set_memory_limit(512 <<< 20)
    _ = ITB.set_gc_percent(20)

    profile = BenchUtil.env("ITB_PROFILE", "streaming-noaead-triple-v1")
    {:ok, pipe} = ITB.init(profile, BenchUtil.bench_opts())
    BenchUtil.header()

    for size <- [1 <<< 20, 16 <<< 20, 64 <<< 20] do
      # CSPRNG-fill so plaintext content matches the root Go bench
      # (crypto/rand). Not in the timing loop.
      plain = :crypto.strong_rand_bytes(size)
      run = fn -> pump(pipe, plain) end
      BenchUtil.bench_case("stream_pump", size, @min_iters, run)

      # Pre-encrypt one wire outside the decrypt timing loop.
      dec_wire = pump_all(pipe, plain)
      run_dec = fn -> pump_dec(pipe, dec_wire) end
      BenchUtil.bench_case("stream_pump-dec", size, @min_iters, run_dec)
    end

    :ok = ITB.free(pipe)
  end

  # Full incremental encrypt session over one buffer.
  defp pump(pipe, plain) do
    {:ok, session} = ITB.encrypt_stream(pipe)
    :ok = feed(session, plain)
    :ok = ITB.stream_end(session)
    :ok = drain(session)
    :ok = ITB.stream_free(session)
  end

  defp feed(_session, <<>>), do: :ok

  defp feed(session, data) do
    n = min(byte_size(data), @pump_buf)
    <<slice::binary-size(^n), rest::binary>> = data
    :ok = ITB.stream_write(session, slice)
    # A read before end never blocks; drain whatever the chain has
    # produced so far to bound the Go-side spool.
    :ok = drain_ready(session)
    feed(session, rest)
  end

  defp drain_ready(session) do
    case ITB.stream_read(session, @pump_buf) do
      {:ok, <<>>, _} -> :ok
      {:ok, _, true} -> :ok
      {:ok, _, false} -> drain_ready(session)
    end
  end

  defp drain(session) do
    case ITB.stream_read(session, @pump_buf) do
      {:ok, _, true} -> :ok
      {:ok, _, false} -> drain(session)
    end
  end

  # Encrypt whole plain, collecting wire. Uses feed_noread so no
  # encoder-produced bytes are lost to drain_ready's read-and-discard
  # pattern: drain_ready's job in the `pump` shape is to bound the
  # Go-side spool during a throwaway encrypt, so it reads chunks off
  # the spool and drops them. In pump_all the wire needs to be
  # preserved, so any drain_ready call landing after a real encoder
  # chunk has been produced would silently drop that chunk. At small
  # plaintext sizes (single-chunk plaintexts fitting in the 16 MiB
  # DefaultChunkSize) the encoder emits nothing until stream_end and
  # drain_ready during feed is a no-op — but at multi-chunk sizes
  # (64 MiB and above) the encoder produces one output per full chunk
  # consumed, and drain_ready between feed slices can catch and drop
  # those chunks before drain_collect at end sees them.
  #
  # Go core wrapper-nonce batching fix (streams.go +
  # wrapper.NewWrapWriter) closes the earlier wrapper-nonce
  # split-write race so a single-chunk pump_all with plain feed would
  # now produce a wire whose nonce is not stranded, but drain_ready's
  # byte-dropping behaviour remains fundamentally incompatible with
  # wire collection across chunk boundaries.
  defp pump_all(pipe, plain) do
    {:ok, session} = ITB.encrypt_stream(pipe)
    :ok = feed_noread(session, plain)
    :ok = ITB.stream_end(session)
    wire = drain_collect(session, [])
    :ok = ITB.stream_free(session)
    wire
  end

  defp feed_noread(_session, <<>>), do: :ok

  defp feed_noread(session, data) do
    n = min(byte_size(data), @pump_buf)
    <<slice::binary-size(^n), rest::binary>> = data
    :ok = ITB.stream_write(session, slice)
    feed_noread(session, rest)
  end

  defp drain_collect(session, acc) do
    case ITB.stream_read(session, @pump_buf) do
      {:ok, chunk, true} -> IO.iodata_to_binary(Enum.reverse([chunk | acc]))
      {:ok, chunk, false} -> drain_collect(session, [chunk | acc])
    end
  end

  defp pump_dec(pipe, wire) do
    {:ok, session} = ITB.decrypt_stream(pipe)
    :ok = feed(session, wire)
    :ok = ITB.stream_end(session)
    :ok = drain(session)
    :ok = ITB.stream_free(session)
  end
end

BenchStream.main()
