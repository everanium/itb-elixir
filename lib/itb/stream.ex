defmodule ITB.Stream do
  @moduledoc """
  Lazy Elixir `Stream` adapters over ITB incremental sessions.

  `encrypt/3` and `decrypt/3` wrap one caller-driven session
  (`ITB.encrypt_stream/1` / `ITB.decrypt_stream/1` plus the
  write / end / read loop) into a lazy transformation over any
  enumerable of chunks: each input chunk is fed to the session and
  whatever the cipher chain has produced so far is emitted, with the
  terminal drain emitted when the enumerable is exhausted. Nothing
  runs until the stream is consumed, and memory stays bounded by the
  chunk and drain-slice sizes regardless of total payload length.

      wire_chunks =
        File.stream!("plain.bin", 1_048_576)
        |> then(&ITB.stream_encrypt(pipeline, &1))
        |> Enum.into([])

  The session is opened when consumption starts and released when
  the stream terminates — normal exhaustion, a raise, or a
  downstream halt (e.g. `Stream.take/2`) all release it; a halted
  encrypt session is cancelled, not finalised, so its output is not
  a decryptable wire. The parent pipeline must stay alive for the
  whole consumption and remains owned by the caller.

  A lazy stream has no channel for error tuples, so failures raise
  `ITB.Error` from the consuming process. Streaming-decrypt caveat:
  chunked Streaming AEAD verifies per chunk, so plaintext of
  verified chunks is emitted before a later chunk can fail
  authentication.
  """

  # Default drain slice (1 MiB), matching ITB.stream_read/1.
  @read_slice 1_048_576

  @doc """
  Lazily encrypts `enumerable` (chunks of iodata) through one
  incremental session on `pipeline`, returning a `Stream` of wire
  binaries.

  Options:

    * `:read_slice` — drain-slice size in bytes (default 1 MiB).
  """
  @spec encrypt(ITB.pipeline(), Enumerable.t(), keyword()) :: Enumerable.t()
  def encrypt(pipeline, enumerable, opts \\ []),
    do: transform(pipeline, enumerable, :encrypt, opts)

  @doc """
  Lazily decrypts `enumerable` (chunks of a wire) through one
  incremental session on `pipeline`, returning a `Stream` of
  plaintext binaries. Options as `encrypt/3`.
  """
  @spec decrypt(ITB.pipeline(), Enumerable.t(), keyword()) :: Enumerable.t()
  def decrypt(pipeline, enumerable, opts \\ []),
    do: transform(pipeline, enumerable, :decrypt, opts)

  defp transform(pipeline, enumerable, direction, opts) do
    read_slice = Keyword.get(opts, :read_slice, @read_slice)

    Stream.transform(
      enumerable,
      fn -> begin!(pipeline, direction) end,
      fn chunk, session ->
        :ok = ok!(ITB.stream_write(session, chunk))
        # A read before end never blocks; drain whatever the chain
        # has produced so far to bound the Go-side spool.
        {drain_ready(session, read_slice, []), session}
      end,
      fn session ->
        :ok = ok!(ITB.stream_end(session))
        {drain_all(session, read_slice, []), session}
      end,
      fn session -> ITB.stream_free(session) end
    )
  end

  defp begin!(pipeline, :encrypt), do: ITB.encrypt_stream!(pipeline)
  defp begin!(pipeline, :decrypt), do: ITB.decrypt_stream!(pipeline)

  defp ok!(:ok), do: :ok
  defp ok!({:error, reason}), do: raise(ITB.Error, reason)

  defp drain_ready(session, read_slice, acc) do
    case ITB.stream_read(session, read_slice) do
      {:ok, <<>>, _finished} -> emit(acc)
      {:ok, piece, false} -> drain_ready(session, read_slice, [piece | acc])
      {:ok, piece, true} -> emit([piece | acc])
      {:error, reason} -> raise(ITB.Error, reason)
    end
  end

  defp drain_all(session, read_slice, acc) do
    case ITB.stream_read(session, read_slice) do
      {:ok, piece, true} -> emit([piece | acc])
      {:ok, piece, false} -> drain_all(session, read_slice, [piece | acc])
      {:error, reason} -> raise(ITB.Error, reason)
    end
  end

  defp emit(acc) do
    acc |> Enum.reverse() |> Enum.reject(&(&1 == <<>>))
  end
end
