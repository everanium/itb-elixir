defmodule Loop.Size do
  @moduledoc """
  Size and duration parsing, the monotonic clock, and the human
  renderings of sizes, rates and durations. Every rendering here is
  part of the output contract shared with the Go harness and the other
  bindings' loop utilities, so the formats are fixed to the character,
  not to taste.
  """

  @suffixes [
    {"KIB", 1024},
    {"KB", 1024},
    {"K", 1024},
    {"MIB", 1024 * 1024},
    {"MB", 1024 * 1024},
    {"M", 1024 * 1024},
    {"GIB", 1024 * 1024 * 1024},
    {"GB", 1024 * 1024 * 1024},
    {"G", 1024 * 1024 * 1024},
    {"B", 1}
  ]

  @units [{"ns", 1.0}, {"us", 1.0e3}, {"ms", 1.0e6}, {"s", 1.0e9}, {"m", 60.0e9},
          {"h", 3600.0e9}]

  @doc """
  Parses a human byte-size string (`16MB`, `1MiB`, `512K`,
  `1073741824`) into a byte count. Every suffix is a binary multiple:
  K/KB/KiB = 1024, M/MB/MiB = 1024^2, G/GB/GiB = 1024^3, B or none =
  bytes; matching is case-insensitive and surrounding whitespace is
  trimmed.
  """
  @spec parse_size(String.t()) :: {:ok, non_neg_integer()} | :error
  def parse_size(s) do
    upper = s |> String.trim() |> String.upcase()

    if upper == "" do
      :error
    else
      {digits, mult} = split_suffix(upper)
      digits = String.trim_trailing(digits)

      cond do
        digits == "" -> :error
        not String.match?(digits, ~r/^[0-9]+$/) -> :error
        true -> {:ok, String.to_integer(digits) * mult}
      end
    end
  end

  defp split_suffix(upper) do
    Enum.find_value(@suffixes, {upper, 1}, fn {suffix, mult} ->
      if String.ends_with?(upper, suffix) do
        {binary_part(upper, 0, byte_size(upper) - byte_size(suffix)), mult}
      end
    end)
  end

  @doc """
  Parses the Go duration grammar — a sequence of decimal numbers each
  followed by a unit (h, m, s, ms, us, ns), such as `30s`, `5m`,
  `1h30m`, `1.5s` — into nanoseconds.
  """
  @spec parse_duration(String.t()) :: {:ok, integer()} | :error
  def parse_duration(""), do: :error
  def parse_duration(s), do: duration_parts(s, 0.0)

  defp duration_parts("", total) when total <= 9.2e18, do: {:ok, trunc(total)}
  defp duration_parts("", _total), do: :error

  defp duration_parts(s, total) do
    with {value, rest} <- number_prefix(s),
         {mult, rest2} <- unit_prefix(rest) do
      duration_parts(rest2, total + value * mult)
    else
      :error -> :error
    end
  end

  # A decimal run with an optional fraction. A leading sign is not
  # part of the grammar.
  defp number_prefix(s) do
    case Regex.run(~r/^[0-9.]+/, s) do
      nil ->
        :error

      [digits] ->
        rest = binary_part(s, byte_size(digits), byte_size(s) - byte_size(digits))

        case Float.parse(digits) do
          {value, ""} -> {value, rest}
          _ -> :error
        end
    end
  end

  defp unit_prefix(s) do
    Enum.find_value(@units, :error, fn {unit, mult} ->
      if String.starts_with?(s, unit) do
        tail = binary_part(s, byte_size(unit), byte_size(s) - byte_size(unit))
        # A longer word starting with this unit is not this unit.
        if String.match?(tail, ~r/^[a-zA-Z]/), do: nil, else: {mult, tail}
      end
    end)
  end

  @doc "Monotonic wall clock in nanoseconds."
  @spec now_ns() :: integer()
  def now_ns, do: System.monotonic_time(:nanosecond)

  @doc ~S"""
  Renders a byte count with a binary-unit suffix: `1.0GiB`, `16.0MiB`,
  `4.0KiB`, `512B`.
  """
  @spec human_bytes(integer()) :: String.t()
  def human_bytes(n) when n >= 1024 * 1024 * 1024, do: f1(n / (1024 * 1024 * 1024)) <> "GiB"
  def human_bytes(n) when n >= 1024 * 1024, do: f1(n / (1024 * 1024)) <> "MiB"
  def human_bytes(n) when n >= 1024, do: f1(n / 1024) <> "KiB"
  def human_bytes(n), do: Integer.to_string(n) <> "B"

  @doc "Renders a possibly-negative byte delta with an explicit sign."
  @spec human_bytes_signed(integer()) :: String.t()
  def human_bytes_signed(n) when n < 0, do: "-" <> human_bytes(-n)
  def human_bytes_signed(n), do: "+" <> human_bytes(n)

  @doc """
  Binary MiB per second over a nanosecond window; 0 when the window is
  unmeasured.
  """
  @spec mb_per_sec(integer(), integer()) :: float()
  def mb_per_sec(_bytes, ns) when ns <= 0, do: 0.0
  def mb_per_sec(bytes, ns), do: bytes / (1024 * 1024) / (ns / 1.0e9)

  @doc ~S"""
  Renders a throughput as `123.4MB/s` (binary MiB per second) or `n/a`
  for an unmeasured window.
  """
  @spec human_rate(integer(), integer()) :: String.t()
  def human_rate(_bytes, ns) when ns <= 0, do: "n/a"
  def human_rate(bytes, ns), do: f1(mb_per_sec(bytes, ns)) <> "MB/s"

  @doc ~S"""
  Renders a duration the way Go's `time.Duration` prints: below one
  second as milliseconds (`900ms`, `1.5ms`); otherwise `[Hh][Mm]Ss`
  where the hour part appears when non-zero, the minute part when the
  hour part appears or the minutes are non-zero, and the seconds carry
  their fraction with trailing zeros removed (`5s`, `5.003s`, `1m0s`,
  `1m5.25s`, `1h0m0s`). The caller rounds first.
  """
  @spec human_duration(integer()) :: String.t()
  def human_duration(ns0) do
    ns = abs(ns0)

    cond do
      ns == 0 ->
        "0s"

      ns < 1_000_000_000 ->
        # The remainder is scaled to nine digits so the fraction
        # renderer is the same one the seconds branch uses.
        Integer.to_string(div(ns, 1_000_000)) <>
          fraction(rem(ns, 1_000_000) * 1000) <> "ms"

      true ->
        hours = div(ns, 3_600_000_000_000)
        rem1 = rem(ns, 3_600_000_000_000)
        minutes = div(rem1, 60_000_000_000)
        rem2 = rem(rem1, 60_000_000_000)
        seconds = div(rem2, 1_000_000_000)
        frac = rem(rem2, 1_000_000_000)

        hpart = if hours > 0, do: Integer.to_string(hours) <> "h", else: ""
        mpart = if hours > 0 or minutes > 0, do: Integer.to_string(minutes) <> "m", else: ""
        hpart <> mpart <> Integer.to_string(seconds) <> fraction(frac) <> "s"
    end
  end

  # The fractional part of a nanosecond remainder (0 .. 1e9) as ".ddd"
  # with trailing zeros removed; empty for zero.
  defp fraction(0), do: ""

  defp fraction(frac_ns) do
    case frac_ns |> Integer.to_string() |> String.pad_leading(9, "0")
         |> String.trim_trailing("0") do
      "" -> ""
      trimmed -> "." <> trimmed
    end
  end

  @doc "A float with one decimal, never in exponent form."
  @spec f1(number()) :: String.t()
  def f1(v), do: :erlang.float_to_binary(v / 1, decimals: 1)

  @doc "A float with two decimals, never in exponent form."
  @spec f2(number()) :: String.t()
  def f2(v), do: :erlang.float_to_binary(v / 1, decimals: 2)

  @doc "A float with three decimals, never in exponent form."
  @spec f3(number()) :: String.t()
  def f3(v), do: :erlang.float_to_binary(v / 1, decimals: 3)
end
