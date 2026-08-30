defmodule ITB.StreamLazyTest do
  # Lazy `ITB.Stream` adapters: chunked enumerable in, Elixir Stream
  # of produced binaries out, one incremental session per
  # consumption, released by the after-function on every termination
  # path (exhaustion, downstream halt, raise).
  use ExUnit.Case

  import ITBTest.Util, only: [pair: 2]

  test "lazy encrypt / decrypt round trip over chunked enumerables" do
    {sender, receiver} = pair("streaming-aead-triple-mac-v1", %{})
    plain = :crypto.strong_rand_bytes(300_000)

    wire =
      sender
      |> ITB.stream_encrypt(chunks(plain, 4096))
      |> Enum.into(<<>>)

    assert byte_size(wire) > byte_size(plain)

    back =
      receiver
      |> ITB.stream_decrypt(chunks(wire, 7333))
      |> Enum.into(<<>>)

    assert back == plain
    :ok = ITB.free(receiver)
    :ok = ITB.free(sender)
  end

  test "empty enumerable still finalises to a decryptable wire" do
    {sender, receiver} = pair("streaming-aead-triple-mac-v1", %{})
    wire = sender |> ITB.stream_encrypt([]) |> Enum.into(<<>>)
    assert byte_size(wire) > 0
    assert receiver |> ITB.stream_decrypt([wire]) |> Enum.into(<<>>) == <<>>
    :ok = ITB.free(receiver)
    :ok = ITB.free(sender)
  end

  test "construction is lazy; consumption opens the session" do
    {:ok, pipe} = ITB.init("streaming-aead-triple-mac-v1")
    :ok = ITB.free(pipe)

    # Building the stream touches nothing — the freed handle only
    # surfaces when consumption opens the session.
    lazy = ITB.stream_encrypt(pipe, ["chunk"])
    err = assert_raise ITB.Error, fn -> Enum.to_list(lazy) end
    assert err.status == :bad_handle
  end

  test "downstream halt cancels the session and leaves the Pipeline usable" do
    {:ok, sender} = ITB.init("streaming-aead-triple-mac-v1")
    plain = :crypto.strong_rand_bytes(1_000_000)

    # Take one produced piece and halt; the after-function frees the
    # session mid-flight.
    [piece | _] =
      sender
      |> ITB.stream_encrypt(chunks(plain, 65_536), read_slice: 4096)
      |> Enum.take(1)

    assert byte_size(piece) > 0

    # The Pipeline stays usable after the halted session.
    {:ok, wire} = ITB.encrypt_message(sender, "after halt")
    assert byte_size(wire) > 0
    :ok = ITB.free(sender)
  end

  test "undecryptable input raises ITB.Error from the consuming process" do
    {sender, receiver} = pair("streaming-aead-triple-mac-v1", %{})
    # Keep the sender's blob valid but feed the receiver noise that
    # cannot be a wire.
    garbage = :crypto.strong_rand_bytes(4096)

    assert_raise ITB.Error, fn ->
      receiver |> ITB.stream_decrypt([garbage]) |> Enum.to_list()
    end

    :ok = ITB.free(receiver)
    :ok = ITB.free(sender)
  end

  # Splits a binary into a lazy enumerable of `size`-byte chunks.
  defp chunks(data, size) do
    Stream.unfold(data, fn
      <<>> ->
        nil

      rest ->
        n = min(byte_size(rest), size)
        <<chunk::binary-size(^n), tail::binary>> = rest
        {chunk, tail}
    end)
  end
end
