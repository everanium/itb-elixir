defmodule Loop.Payload do
  @moduledoc """
  Plaintext content: the payload modes, the seeded per-worker
  generator, and the buffer fill from the operating-system CSPRNG.

  The modes the `--payload-mode` flag selects:

    * `:fixed` — one CSPRNG-generated buffer per worker, held
      unchanged for the whole run (the default).
    * `:rotating` — the buffer is regenerated before every iteration,
      so no two encrypt calls see the same plaintext.
    * `:pattern_zero` / `:pattern_ff` — degenerate constant fills (all
      `0x00` / all `0xFF`) probing minimum-entropy plaintext handling.
    * `:pattern_ascii` — a repeating `A`..`Z` ramp probing low-entropy
      structured text.
  """

  import Bitwise

  @m64 0xFFFFFFFFFFFFFFFF

  @spec mode_name(atom()) :: String.t()
  def mode_name(:fixed), do: "fixed"
  def mode_name(:rotating), do: "rotating"
  def mode_name(:pattern_zero), do: "pattern-zero"
  def mode_name(:pattern_ff), do: "pattern-ff"
  def mode_name(:pattern_ascii), do: "pattern-ascii"

  @spec parse_mode(String.t()) :: {:ok, atom()} | :error
  def parse_mode("fixed"), do: {:ok, :fixed}
  def parse_mode("rotating"), do: {:ok, :rotating}
  def parse_mode("pattern-zero"), do: {:ok, :pattern_zero}
  def parse_mode("pattern-ff"), do: {:ok, :pattern_ff}
  def parse_mode("pattern-ascii"), do: {:ok, :pattern_ascii}
  def parse_mode(_), do: :error

  @doc """
  Seeded plaintext. The seed makes plaintext content reproducible so a
  failing iteration can be replayed with the same bytes; it governs
  nothing else — pipeline keys, nonces and masters stay CSPRNG-drawn,
  so a seeded run is a reproduction aid and never a security test.
  Each worker's stream is domain-separated by its id so seeded workers
  still hold pairwise-distinct buffers under the fixed and rotating
  modes. The generator is splitmix64: a few lines in any language,
  which is why it is the one every binding uses.
  """
  @spec seed_worker(non_neg_integer(), non_neg_integer()) :: non_neg_integer()
  def seed_worker(seed, worker_id), do: (seed + worker_id + 1) &&& @m64

  defp splitmix64(state0) do
    s = state0 + 0x9E3779B97F4A7C15 &&& @m64
    z1 = bxor(s, s >>> 30) * 0xBF58476D1CE4E5B9 &&& @m64
    z2 = bxor(z1, z1 >>> 27) * 0x94D049BB133111EB &&& @m64
    {bxor(z2, z2 >>> 31), s}
  end

  @doc "Draws `n` bytes from the operating-system CSPRNG."
  @spec random_bytes(non_neg_integer()) :: binary()
  def random_bytes(n), do: :crypto.strong_rand_bytes(n)

  @doc """
  Builds one plaintext buffer according to the payload mode. The fixed
  and rotating modes draw from the seeded generator when the run is
  seeded and from the OS CSPRNG otherwise; the pattern modes are
  deterministic regardless of the seed. Returns the buffer and the
  generator state to carry into the next fill.
  """
  @spec fill(atom(), boolean(), non_neg_integer(), non_neg_integer()) ::
          {binary(), non_neg_integer()}
  def fill(mode, false, rng, n) when mode in [:fixed, :rotating], do: {random_bytes(n), rng}
  def fill(mode, true, rng, n) when mode in [:fixed, :rotating], do: seeded_fill(rng, n, [])
  def fill(:pattern_zero, _seeded, rng, n), do: {:binary.copy(<<0>>, n), rng}
  def fill(:pattern_ff, _seeded, rng, n), do: {:binary.copy(<<0xFF>>, n), rng}
  def fill(:pattern_ascii, _seeded, rng, n), do: {ascii_ramp(n), rng}

  # Eight little-endian bytes per generator draw, the last draw
  # truncated to the bytes the buffer still wants.
  defp seeded_fill(rng, n, acc) when n <= 0,
    do: {acc |> Enum.reverse() |> IO.iodata_to_binary(), rng}

  defp seeded_fill(rng, n, acc) do
    {v, rng1} = splitmix64(rng)
    word = <<v::little-64>>

    if n >= 8 do
      seeded_fill(rng1, n - 8, [word | acc])
    else
      seeded_fill(rng1, 0, [binary_part(word, 0, n) | acc])
    end
  end

  # Byte i is 'A' + rem(i, 26), built from one 26-byte period so a
  # large buffer costs a copy rather than a per-byte comprehension.
  defp ascii_ramp(n) do
    period = ?A..?Z |> Enum.to_list() |> :erlang.list_to_binary()
    :binary.copy(period, div(n, 26)) <> binary_part(period, 0, rem(n, 26))
  end
end
