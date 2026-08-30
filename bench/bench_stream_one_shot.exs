# bench_stream_one_shot — whole-buffer stream throughput vs plaintext
# size (Streaming Non-AEAD profile) at 1 MiB / 16 MiB / 64 MiB. Each
# iteration issues one ITB.encrypt_stream_one_shot/2 or
# ITB.decrypt_stream_one_shot/2 call for callers holding the full
# payload in memory — the whole-buffer fast path through libitb.
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
#   mix run bench/bench_stream_one_shot.exs

Code.require_file("bench_util.exs", __DIR__)

defmodule BenchStreamOneShot do
  import Bitwise

  @min_iters 3

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

      run = fn ->
        {:ok, _wire} = ITB.encrypt_stream_one_shot(pipe, plain)
        :ok
      end

      BenchUtil.bench_case("stream_one_shot", size, @min_iters, run)

      # Pre-encrypt one wire outside the decrypt timing loop.
      {:ok, dec_wire} = ITB.encrypt_stream_one_shot(pipe, plain)

      run_dec = fn ->
        {:ok, _plain} = ITB.decrypt_stream_one_shot(pipe, dec_wire)
        :ok
      end

      BenchUtil.bench_case("stream_one_shot-dec", size, @min_iters, run_dec)
    end

    :ok = ITB.free(pipe)
  end
end

BenchStreamOneShot.main()
