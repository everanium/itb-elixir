# bench_util — shared timing loop + env plumbing for the bench
# scripts. Loaded via Code.require_file; not part of the library.

defmodule BenchUtil do
  import Bitwise

  def header do
    :io.format(~c"~-17s ~-8s ~s~n", [~c"bench", ~c"size", ~c"mb_per_sec"])
  end

  # Timing loop: one untimed warm-up, then iterate until the
  # wall-clock budget is spent (with an iteration floor); print one
  # table row.
  def bench_case(name, size, min_iters, run) do
    # Warm-up.
    :ok = run.()
    budget = min_seconds()
    start = System.monotonic_time(:microsecond)
    iters = loop(run, start, budget, min_iters, 0)
    elapsed = (System.monotonic_time(:microsecond) - start) / 1.0e6
    mb = size * iters / (1024 * 1024)
    :io.format(~c"~-17s ~-8s ~.1f~n", [name, size_label(size), mb / elapsed])
    :ok
  end

  defp loop(run, start, budget, min_iters, iters) do
    :ok = run.()
    elapsed = (System.monotonic_time(:microsecond) - start) / 1.0e6

    if elapsed < budget or iters + 1 < min_iters do
      loop(run, start, budget, min_iters, iters + 1)
    else
      iters + 1
    end
  end

  defp size_label(size) when size >= 1 <<< 20, do: "#{size >>> 20} MiB"
  defp size_label(size), do: "#{size >>> 10} KiB"

  defp min_seconds do
    case Float.parse(env("ITB_BENCH_MIN_SEC", "5")) do
      {f, _} when f > 0 -> f
      _ -> 5.0
    end
  end

  # Bench-shape opts from env (defaults per bindings/BENCH.md).
  def bench_opts do
    base = %{
      "nonceBits" => env("ITB_NONCE_BITS", "512"),
      "keyBits" => env("ITB_KEY_BITS", "1024"),
      "withParallax" => flag(env("ITB_WITH_PARALLAX", "false")),
      "withWrapper" => flag(env("ITB_WITH_WRAPPER", "false"))
    }

    base =
      case env("ITB_INNER_HASH", "") do
        "" -> base
        hash -> Map.put(base, "innerHash", hash)
      end

    case env("ITB_MAC_NAME", "") do
      "" -> base
      mac -> Map.put(base, "macName", mac)
    end
  end

  defp flag(raw) when raw in ["true", "1"], do: "true"
  defp flag(_), do: "false"

  def env(name, default) do
    case System.get_env(name) do
      nil -> default
      "" -> default
      value -> value
    end
  end
end
