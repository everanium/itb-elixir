# bench_message — encrypt_message throughput vs plaintext size
# (Single Message profile) at 1 MiB / 16 MiB / 64 MiB.
#
# Env-var overrides (defaults match the root Go BENCH3.md pin so the
# numbers are directly comparable):
#
#   ITB_PROFILE        singlemsg-triple-nomac-v1
#   ITB_INNER_HASH     areion512
#   ITB_KEY_BITS       1024
#   ITB_NONCE_BITS     512
#   ITB_WITH_PARALLAX  false
#   ITB_WITH_WRAPPER   false
#   ITB_BENCH_MIN_SEC  5
#
# Invocation (from bindings/elixir, after ./build.sh):
#   mix run bench/bench_message.exs

Code.require_file("bench_util.exs", __DIR__)

defmodule BenchMessage do
  import Bitwise

  @min_iters 3

  def main do
    # Bench-scale allocation churn leaks Go scratch heap unboundedly
    # without a soft memory cap + aggressive GC; the return values
    # report the previous settings, not an error.
    _ = ITB.set_memory_limit(512 <<< 20)
    _ = ITB.set_gc_percent(20)

    profile = BenchUtil.env("ITB_PROFILE", "singlemsg-triple-nomac-v1")
    {:ok, pipe} = ITB.init(profile, BenchUtil.bench_opts())
    BenchUtil.header()

    for size <- [1 <<< 20, 16 <<< 20, 64 <<< 20] do
      # CSPRNG-fill so plaintext content matches the root Go bench
      # (crypto/rand). Not in the timing loop.
      plain = :crypto.strong_rand_bytes(size)

      run = fn ->
        {:ok, _wire} = ITB.encrypt_message(pipe, plain)
        :ok
      end

      BenchUtil.bench_case("message", size, @min_iters, run)

      # Pre-encrypt one wire outside the decrypt timing loop.
      {:ok, dec_wire} = ITB.encrypt_message(pipe, plain)
      run_dec = fn ->
        {:ok, _plain} = ITB.decrypt_message(pipe, dec_wire)
        :ok
      end
      BenchUtil.bench_case("message-dec", size, @min_iters, run_dec)
    end

    :ok = ITB.free(pipe)
  end
end

BenchMessage.main()
