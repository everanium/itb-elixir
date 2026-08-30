defmodule ITB.StreamStickyTest do
  # A decrypt session fed a tampered wire fails with a sticky
  # mac_failure.
  #
  # A single bit flip can land in the container's CSPRNG residue —
  # over-sized container area that carries no payload — where the
  # decrypt legitimately completes clean. Successive flip positions
  # are therefore probed, each against a fresh session on a fresh
  # copy of the wire, until one lands in authenticated content; the
  # observed failure must be mac_failure and must be sticky. The
  # probe is black-box — no wire-layout knowledge is used.
  use ExUnit.Case

  import ITBTest.Util, only: [pair: 2, pump: 3, flip_byte: 2]

  test "tampered wire fails with sticky mac_failure" do
    {sender, receiver} = pair("streaming-aead-triple-mac-v1", %{})
    plain = :crypto.strong_rand_bytes(65_536)
    wire = pump(sender, :encrypt, plain)
    assert probe(receiver, wire, 0)
    :ok = ITB.free(receiver)
    :ok = ITB.free(sender)
  end

  # Flip positions walk the wire body (starting at the 3/4 mark with
  # a 1031-byte stride) so the probe stays clear of the outer framing
  # header, whose corruption fails structurally before
  # authentication.
  defp probe(_receiver, _wire, attempt) when attempt >= 32, do: false

  defp probe(receiver, wire, attempt) do
    wire_len = byte_size(wire)
    pos = rem(div(wire_len * 3, 4) + attempt * 1031, wire_len)
    tampered = flip_byte(wire, pos)
    {:ok, session} = ITB.decrypt_stream(receiver)
    # The failure may surface on write (chain already failed) or on
    # a later read — either way a read must eventually report it.
    _ = ITB.stream_write(session, tampered)
    _ = ITB.stream_end(session)

    verdict =
      case drain_to_status(session) do
        :clean ->
          # Flip landed in residue — try the next position.
          :next

        {:error, {:mac_failure, _}} ->
          # Sticky: a subsequent read reports a failure again.
          case ITB.stream_read(session, 4096) do
            {:error, {:mac_failure, _}} -> true
            other -> {:unexpected_second, other}
          end

        other ->
          {:unexpected_first, other}
      end

    :ok = ITB.stream_free(session)

    case verdict do
      true -> true
      :next -> probe(receiver, wire, attempt + 1)
      unexpected -> flunk("expected sticky mac_failure, got #{inspect(unexpected)}")
    end
  end

  defp drain_to_status(session) do
    case ITB.stream_read(session, 4096) do
      {:ok, _, true} -> :clean
      {:ok, _, false} -> drain_to_status(session)
      {:error, reason} -> {:error, reason}
    end
  end
end
