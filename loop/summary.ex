defmodule Loop.Summary do
  @moduledoc """
  The final summary in both renderings, and the two measurements it
  folds in that are not per-worker counters: the process resident set
  and the shared library's pool counters.
  """

  alias Loop.{Config, Payload, Run, Size, State, Worker, WStats}

  @concurrency "shared-handle"

  # ------------------------------------------------------------------
  # Resident set
  # ------------------------------------------------------------------

  @doc """
  The process's current resident set and its high-water mark in bytes,
  from `/proc/self/status` (`VmRSS` and `VmHWM`, reported in kB). Both
  are zero on a platform without that file; the figures are
  informational and never enter the verdict.
  """
  @spec read_rss() :: {non_neg_integer(), non_neg_integer()}
  def read_rss do
    case File.read("/proc/self/status") do
      {:ok, text} ->
        text
        |> String.split("\n")
        |> Enum.reduce({0, 0}, fn line, {cur, peak} ->
          cond do
            String.starts_with?(line, "VmRSS:") -> {status_kb(line), peak}
            String.starts_with?(line, "VmHWM:") -> {cur, status_kb(line)}
            true -> {cur, peak}
          end
        end)

      _ ->
        {0, 0}
    end
  end

  defp status_kb(line) do
    case Regex.run(~r/(\d+)/, line) do
      [_, kb] -> String.to_integer(kb) * 1024
      _ -> 0
    end
  end

  # ------------------------------------------------------------------
  # Pool counters
  # ------------------------------------------------------------------

  @doc """
  Pool counters. The shared library keeps process-wide monotonic
  totals at every pool checkout of its cipher core: per hash-array
  tier the starter width, checkouts, constructor misses, regrow
  replacements and bytes allocated; for the scratch byte pool and the
  parallax chunk pool the checkouts, constructor misses, regrows and
  regrow bytes. Two snapshots bracketing the main loop are differenced
  into per-run hit / miss figures that tell whether a pool keeps its
  items warm between calls or evicts them across GC cycles. The slot
  layout is read from the library: slot 0 carries the tier count `t`,
  tier `i` occupies the five slots at `1 + 5*i`, and the two byte
  pools occupy the eight slots at `1 + 5*t`; the vector is sized by
  the binding's length query, never by a constant.
  """
  @spec pool_snapshot() :: [integer()]
  def pool_snapshot do
    case ITB.pool_stats() do
      {:ok, slots} -> slots
      {:error, _} -> []
    end
  end

  defp pool_diff(warmup, steady) when length(warmup) < 9 or length(steady) < 9,
    do: {[], zero_pool(), zero_pool()}

  defp pool_diff(warmup, steady) do
    w = List.to_tuple(warmup)
    s = List.to_tuple(steady)
    tiers = elem(s, 0)

    if tiers < 0 or 1 + 5 * tiers + 8 > tuple_size(s) do
      {[], zero_pool(), zero_pool()}
    else
      tier_list =
        for i <- 0..(tiers - 1)//1 do
          %{
            tier: i,
            starter: elem(s, 1 + 5 * i),
            get: elem(s, 2 + 5 * i) - elem(w, 2 + 5 * i),
            new: elem(s, 3 + 5 * i) - elem(w, 3 + 5 * i),
            regrow: elem(s, 4 + 5 * i) - elem(w, 4 + 5 * i),
            new_bytes: elem(s, 5 + 5 * i) - elem(w, 5 + 5 * i)
          }
        end

      tail = 1 + 5 * tiers
      {Enum.filter(tier_list, &(&1.starter != 0)), byte_pool(w, s, tail),
       byte_pool(w, s, tail + 4)}
    end
  end

  defp byte_pool(w, s, base) do
    %{
      get: elem(s, base) - elem(w, base),
      new: elem(s, base + 1) - elem(w, base + 1),
      regrow: elem(s, base + 2) - elem(w, base + 2),
      regrow_bytes: elem(s, base + 3) - elem(w, base + 3)
    }
  end

  defp zero_pool, do: %{get: 0, new: 0, regrow: 0, regrow_bytes: 0}

  # Misses over checkouts as a percentage; zero when nothing was
  # checked out.
  defp miss_percent(_miss, get) when get <= 0, do: 0.0
  defp miss_percent(miss, get), do: 100.0 * miss / get

  # ------------------------------------------------------------------
  # Summary
  # ------------------------------------------------------------------

  @doc """
  Output contract. Both renderings are shared with the Go harness and
  every other binding's loop utility field for field: the same lines
  in the same order, the same keys in the same order, floats with a
  fixed number of decimals so the JSON is byte-identical across
  implementations. The Go harness alone adds its runtime-internal
  lines after `rss:` and its runtime-internal keys after
  `parallax_chunk_pool`; nothing here reproduces them because nothing
  they read is reachable through the binding.
  """
  @spec final(%Run{}, [%WStats{}], integer(), {integer(), integer(), integer()},
              {[integer()], [integer()]}) :: 0 | 1
  def final(%Run{cfg: %Config{} = cfg} = run, stats, elapsed_ns, {rss_warmup, rss_peak,
        rss_final}, {pool_warmup, pool_steady}) do
    total_iters = Enum.sum(Enum.map(stats, & &1.iters))
    total_enc = Enum.sum(Enum.map(stats, & &1.bytes_enc))
    total_dec = Enum.sum(Enum.map(stats, & &1.bytes_dec))
    nanos_enc = Enum.sum(Enum.map(stats, & &1.nanos_enc))
    nanos_dec = Enum.sum(Enum.map(stats, & &1.nanos_dec))
    errors = stats |> Enum.filter(& &1.failed) |> Enum.map(& &1.error)

    # Throughput. Per-direction throughput divides the sum of every
    # worker's wall time in that direction by the worker count — the
    # equivalent single-stream wall time under N-way concurrency — so
    # each direction reports the aggregate rate it sustained rather
    # than collapsing to combined/2 (every iteration moves equal
    # encrypt and decrypt bytes, so a total-elapsed denominator would
    # give both directions the same figure). The combined rate keeps
    # total elapsed as the one-glance overall figure.
    avg_enc = if nanos_enc > 0, do: div(nanos_enc, cfg.workers), else: 0
    avg_dec = if nanos_dec > 0, do: div(nanos_dec, cfg.workers), else: 0

    rss_delta = rss_final - rss_warmup
    rss_growth = if rss_warmup > 0, do: 100.0 * rss_delta / rss_warmup, else: 0.0
    {tiers, buf, chunk} = pool_diff(pool_warmup, pool_steady)
    pass = errors == []
    {stream_pipe, msg_pipe} = State.handles(run.state)

    f = %{
      total_iters: total_iters,
      total_enc: total_enc,
      total_dec: total_dec,
      avg_enc: avg_enc,
      avg_dec: avg_dec,
      elapsed: elapsed_ns,
      errors: errors,
      pass: pass,
      rekeys: State.count(run.counts, :rekeys),
      cycles: State.count(run.counts, :blob_cycles),
      gomaxprocs: ITB.set_gomaxprocs(0),
      stream_profile: if(stream_pipe, do: run.stream_profile, else: ""),
      msg_profile: if(msg_pipe, do: run.msg_profile, else: ""),
      rss_warmup: rss_warmup,
      rss_peak: rss_peak,
      rss_final: rss_final,
      rss_delta: rss_delta,
      rss_growth: rss_growth,
      tiers: tiers,
      buf: buf,
      chunk: chunk,
      stats: stats
    }

    if cfg.json_output, do: json(cfg, f), else: human(cfg, f)
    if pass, do: 0, else: 1
  end

  # ------------------------------------------------------------------

  defp json(cfg, f) do
    Loop.Main.emit(:stdio, [
      "{\"duration_seconds\":", Size.f3(f.elapsed / 1.0e9),
      ",\"iterations\":", i(f.total_iters),
      ",\"per_worker_iterations\":[",
      Enum.map_join(f.stats, ",", &i(&1.iters)), "]",
      ",\"bytes_encrypted\":", i(f.total_enc),
      ",\"bytes_decrypted\":", i(f.total_dec),
      ",\"encrypt_mb_per_sec\":", Size.f1(Size.mb_per_sec(f.total_enc, f.avg_enc)),
      ",\"decrypt_mb_per_sec\":", Size.f1(Size.mb_per_sec(f.total_dec, f.avg_dec)),
      ",\"combined_mb_per_sec\":",
      Size.f1(Size.mb_per_sec(f.total_enc + f.total_dec, f.elapsed)),
      ",\"rekeys\":", i(f.rekeys),
      ",\"blob_cycles\":", i(f.cycles),
      ",\"worker_errors\":[", Enum.map_join(f.errors, ",", &jstr/1), "]",
      ",\"verdict\":", jstr(if f.pass, do: "PASS", else: "FAIL"),
      ",\"shape\":", jstr(Worker.shape_name(cfg.shape)),
      ",\"stream_profile\":", jstr(f.stream_profile),
      ",\"message_profile\":", jstr(f.msg_profile),
      ",\"hash\":", jstr(cfg.hash),
      ",\"mac\":", jstr(cfg.mac),
      ",\"payload_bytes\":", i(cfg.payload),
      ",\"payload_mode\":", jstr(Payload.mode_name(cfg.payload_mode)),
      ",\"seed\":", i(cfg.seed),
      ",\"key_bits\":", i(cfg.key_bits),
      ",\"nonce_bits\":", i(cfg.nonce_bits),
      ",\"blob_mode\":", i(cfg.blob_mode),
      ",\"drbg\":", jstr(cfg.drbg),
      ",\"drbg_auto_tier\":", jstr(drbg_auto_tier()),
      ",\"chunk_size_bytes\":", i(cfg.chunk_size),
      ",\"barrier_fill\":", i(cfg.barrier_fill),
      ",\"parallax\":", jstr(Loop.Main.on_off(cfg.parallax)),
      ",\"wrapper\":", jstr(Loop.Main.on_off(cfg.wrapper)),
      ",\"goroutines_requested\":", i(cfg.workers_requested),
      ",\"goroutines\":", i(cfg.workers),
      ",\"concurrency\":", jstr(@concurrency),
      ",\"gogc\":", jstr(Integer.to_string(effective_gogc(cfg.gogc))),
      ",\"memlimit_bytes\":", i(cfg.memlimit),
      ",\"gomaxprocs\":", i(f.gomaxprocs),
      ",\"microbatch_tiers\":", jstr(Loop.Main.policy_label("ITB_MICROBATCH_TIERS")),
      ",\"hashpool_starters\":", jstr(Loop.Main.policy_label("ITB_HASHPOOL_STARTERS")),
      ",\"rss_warmup_bytes\":", i(f.rss_warmup),
      ",\"rss_peak_bytes\":", i(f.rss_peak),
      ",\"rss_final_bytes\":", i(f.rss_final),
      ",\"rss_growth_percent\":", Size.f2(f.rss_growth),
      ",\"hash_pool_tiers\":[", Enum.map_join(f.tiers, ",", &json_tier/1), "]",
      ",\"buf_pool\":", json_byte_pool(f.buf),
      ",\"parallax_chunk_pool\":", json_byte_pool(f.chunk),
      "}\n"
    ])
  end

  defp json_tier(t) do
    "{\"tier\":#{t.tier},\"starter\":#{t.starter},\"get\":#{t.get},\"new\":#{t.new}" <>
      ",\"regrow\":#{t.regrow},\"new_bytes\":#{t.new_bytes}" <>
      ",\"miss_percent\":#{Size.f2(miss_percent(t.new + t.regrow, t.get))}}"
  end

  defp json_byte_pool(p) do
    "{\"get\":#{p.get},\"new\":#{p.new},\"regrow\":#{p.regrow}" <>
      ",\"regrow_bytes\":#{p.regrow_bytes}" <>
      ",\"miss_percent\":#{Size.f2(miss_percent(p.regrow, p.get))}}"
  end

  defp i(n), do: Integer.to_string(n)

  # The fill cipher the auto DRBG tier selected on this host; empty
  # when the library cannot report it.
  defp drbg_auto_tier do
    case ITB.drbg_auto_tier() do
      {:ok, tier} -> tier
      {:error, _} -> ""
    end
  end

  # One JSON string literal with the escapes JSON requires.
  defp jstr(s) do
    escaped =
      s
      |> IO.iodata_to_binary()
      |> String.to_charlist()
      |> Enum.map(&json_char/1)

    [?", escaped, ?"]
  end

  defp json_char(?"), do: "\\\""
  defp json_char(?\\), do: "\\\\"
  defp json_char(?\n), do: "\\n"
  defp json_char(?\r), do: "\\r"
  defp json_char(?\t), do: "\\t"

  defp json_char(c) when c < 0x20,
    do: "\\u" <> String.pad_leading(Integer.to_string(c, 16), 4, "0")

  defp json_char(c), do: c

  # The effective GC percentage as the runtime reports it: the query
  # form of the setter (a set-and-restore round trip inside the
  # library) so the field is the same whether the value came from the
  # flag, the environment, or the runtime default.
  defp effective_gogc(flag) when flag > 0, do: flag
  defp effective_gogc(_flag), do: ITB.set_gc_percent(-1)

  # ------------------------------------------------------------------

  defp human(cfg, f) do
    log = &Loop.Main.log/1
    log.("=== FINAL ===")
    log.("  duration: #{Size.human_duration(div(f.elapsed + 500_000, 1_000_000) * 1_000_000)}")

    parts = Enum.map_join(f.stats, " + ", &Integer.to_string(&1.iters))
    log.("  iterations: #{parts} = #{f.total_iters} total")

    log.(
      "  throughput: encrypt #{Size.human_rate(f.total_enc, f.avg_enc)}, " <>
        "decrypt #{Size.human_rate(f.total_dec, f.avg_dec)}, " <>
        "combined #{Size.human_rate(f.total_enc + f.total_dec, f.elapsed)}"
    )

    log.(
      "  bytes: #{Size.human_bytes(f.total_enc)} encrypted, " <>
        "#{Size.human_bytes(f.total_dec)} decrypted"
    )

    log.("  data integrity: #{f.total_iters}/#{f.total_iters} PASS")
    log.("  concurrency: #{@concurrency}, workers #{cfg.workers} (requested #{cfg.workers_requested})")

    log.(
      "  rss: warmup #{Size.human_bytes(f.rss_warmup)}, peak #{Size.human_bytes(f.rss_peak)}, " <>
        "final #{Size.human_bytes(f.rss_final)} (delta #{Size.human_bytes_signed(f.rss_delta)}, " <>
        "#{Size.f1(f.rss_growth)}% growth)"
    )

    Enum.each(f.tiers, fn t ->
      log.(
        "  hash pool tier #{t.tier} (starter #{t.starter}): get #{t.get}, " <>
          "miss #{t.new + t.regrow} (new #{t.new} + regrow #{t.regrow}), " <>
          "miss #{Size.f2(miss_percent(t.new + t.regrow, t.get))}%, " <>
          "#{Size.human_bytes(t.new_bytes)} allocated"
      )
    end)

    log.(
      "  buf pool: get #{f.buf.get}, regrow #{f.buf.regrow} (of which fresh #{f.buf.new}), " <>
        "miss #{Size.f2(miss_percent(f.buf.regrow, f.buf.get))}%, " <>
        "#{Size.human_bytes(f.buf.regrow_bytes)} regrown"
    )

    log.(
      "  parallax chunk pool: get #{f.chunk.get}, regrow #{f.chunk.regrow} " <>
        "(of which fresh #{f.chunk.new}), " <>
        "miss #{Size.f2(miss_percent(f.chunk.regrow, f.chunk.get))}%, " <>
        "#{Size.human_bytes(f.chunk.regrow_bytes)} regrown"
    )

    if f.rekeys > 0, do: log.("  rekeys: #{f.rekeys}")
    if f.cycles > 0, do: log.("  blob cycles: #{f.cycles}")
    Enum.each(f.errors, fn e -> log.("  ERROR: #{e}") end)

    if f.pass do
      log.("  verdict: PASS")
    else
      log.("  verdict: FAIL (errors=#{length(f.errors)})")
    end
  end
end
