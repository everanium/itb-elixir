defmodule ITB.StreamPumpTest do
  # Whole-buffer stream pump round trips (1 MiB feed / drain slices)
  # on the Streaming AEAD and Non-AEAD profiles.
  use ExUnit.Case

  import Bitwise
  import ITBTest.Util, only: [pair: 2, pump: 3]

  defp pump_round_trip(profile) do
    {sender, receiver} = pair(profile, %{})
    plain = :crypto.strong_rand_bytes((1 <<< 20) + 12_345)
    wire = pump(sender, :encrypt, plain)
    assert byte_size(wire) > byte_size(plain)
    back = pump(receiver, :decrypt, wire)
    assert back == plain
    :ok = ITB.free(receiver)
    :ok = ITB.free(sender)
  end

  test "Streaming AEAD pump round trip",
    do: pump_round_trip("streaming-aead-triple-mac-v1")

  test "Streaming Non-AEAD pump round trip",
    do: pump_round_trip("streaming-noaead-triple-v1")

  test "sequential sessions on one Pipeline stay independent" do
    {sender, receiver} = pair("streaming-aead-triple-mac-v1", %{})
    plain1 = :crypto.strong_rand_bytes(200_000)
    plain2 = :crypto.strong_rand_bytes(100_000)
    wire1 = pump(sender, :encrypt, plain1)
    wire2 = pump(sender, :encrypt, plain2)
    assert pump(receiver, :decrypt, wire1) == plain1
    assert pump(receiver, :decrypt, wire2) == plain2
    :ok = ITB.free(receiver)
    :ok = ITB.free(sender)
  end

  test "zero-length payload through a full session" do
    {sender, receiver} = pair("streaming-aead-triple-mac-v1", %{})
    wire = pump(sender, :encrypt, <<>>)
    assert byte_size(wire) > 0
    assert pump(receiver, :decrypt, wire) == <<>>
    :ok = ITB.free(receiver)
    :ok = ITB.free(sender)
  end
end
