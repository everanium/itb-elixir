defmodule ITBTest.Util do
  @moduledoc false
  # Shared helpers for the ExUnit suite; mirrors the Erlang binding's
  # itb_test_util module (bindings/erlang/test/itb_test_util.erl).

  import Bitwise

  @slice 1 <<< 20

  @doc "Sender + receiver pipelines over one profile / opts pair."
  def pair(profile, opts \\ %{}) do
    {:ok, sender} = ITB.init(profile, opts)
    {:ok, blob} = ITB.blob(sender)
    {:ok, receiver} = ITB.open(profile, blob, opts)
    {sender, receiver}
  end

  @doc """
  Whole-buffer pump through an incremental session with configurable
  feed / drain slices (1 MiB default): begin -> write slices
  (draining the spool after each write) -> end -> drain until
  finished -> free.
  """
  def pump(pipe, direction, data, write_slice \\ @slice, read_slice \\ @slice) do
    {:ok, session} =
      case direction do
        :encrypt -> ITB.encrypt_stream(pipe)
        :decrypt -> ITB.decrypt_stream(pipe)
      end

    acc = feed(session, data, write_slice, read_slice, [])
    :ok = ITB.stream_end(session)
    out = drain_all(session, read_slice, acc)
    :ok = ITB.stream_free(session)
    out
  end

  defp feed(_session, <<>>, _write_slice, _read_slice, acc), do: acc

  defp feed(session, data, write_slice, read_slice, acc) do
    n = min(byte_size(data), write_slice)
    <<slice::binary-size(^n), rest::binary>> = data
    :ok = ITB.stream_write(session, slice)
    # A read before end never blocks; drain whatever the chain has
    # produced so far to bound the Go-side spool.
    acc = drain_ready(session, read_slice, acc)
    feed(session, rest, write_slice, read_slice, acc)
  end

  defp drain_ready(session, read_slice, acc) do
    case ITB.stream_read(session, read_slice) do
      {:ok, <<>>, _} -> acc
      {:ok, piece, false} -> drain_ready(session, read_slice, [piece | acc])
      {:ok, piece, true} -> [piece | acc]
    end
  end

  defp drain_all(session, read_slice, acc) do
    case ITB.stream_read(session, read_slice) do
      {:ok, piece, true} -> acc |> then(&[piece | &1]) |> Enum.reverse() |> IO.iodata_to_binary()
      {:ok, piece, false} -> drain_all(session, read_slice, [piece | acc])
    end
  end

  @doc "Copy of `wire` with bit 0 of byte `pos` flipped."
  def flip_byte(wire, pos) do
    <<head::binary-size(^pos), byte, tail::binary>> = wire
    <<head::binary, bxor(byte, 1), tail::binary>>
  end
end
