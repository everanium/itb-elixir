defmodule ITB.StreamOneShotTest do
  # One-shot stream round trips (whole buffer in a single call) on the
  # Streaming AEAD and Non-AEAD profiles, wire cross-checks against
  # the incremental session path, tampered-wire rejection, and the
  # bang variants.
  use ExUnit.Case

  import Bitwise
  import ITBTest.Util, only: [pair: 2, pump: 3, flip_byte: 2]

  defp round_trip(profile) do
    {sender, receiver} = pair(profile, %{})

    payloads = [
      <<0>>,
      "any text or binary data",
      :crypto.strong_rand_bytes((1 <<< 18) + 12_345)
    ]

    for plain <- payloads do
      {:ok, wire} = ITB.encrypt_stream_one_shot(sender, plain)
      assert byte_size(wire) > byte_size(plain)
      {:ok, back} = ITB.decrypt_stream_one_shot(receiver, wire)
      assert back == plain
    end

    :ok = ITB.free(receiver)
    :ok = ITB.free(sender)
  end

  test "Streaming AEAD one-shot round trips",
    do: round_trip("streaming-aead-triple-mac-v1")

  test "Streaming Non-AEAD one-shot round trips",
    do: round_trip("streaming-noaead-triple-v1")

  test "one-shot wire interoperates with the incremental session path" do
    {sender, receiver} = pair("streaming-aead-triple-mac-v1", %{})
    plain = :crypto.strong_rand_bytes(262_151)
    {:ok, wire} = ITB.encrypt_stream_one_shot(sender, plain)
    assert pump(receiver, :decrypt, wire) == plain
    wire2 = pump(sender, :encrypt, plain)
    {:ok, back} = ITB.decrypt_stream_one_shot(receiver, wire2)
    assert back == plain
    :ok = ITB.free(receiver)
    :ok = ITB.free(sender)
  end

  test "tampered wire is rejected" do
    # A bit flip in authenticated wire content is rejected by the
    # Streaming AEAD profile's per-chunk MAC. A single flip can land
    # in the container's CSPRNG residue — where the decrypt
    # legitimately completes clean — so successive flip positions are
    # probed until one is rejected.
    {sender, receiver} = pair("streaming-aead-triple-mac-v1", %{})
    plain = :crypto.strong_rand_bytes(65_536)
    {:ok, wire} = ITB.encrypt_stream_one_shot(sender, plain)
    assert probe_flip(receiver, wire, 0)
    :ok = ITB.free(receiver)
    :ok = ITB.free(sender)
  end

  test "bang variants unwrap and raise" do
    {sender, receiver} = pair("streaming-aead-triple-mac-v1", %{})
    plain = :crypto.strong_rand_bytes(4096)
    wire = ITB.encrypt_stream_one_shot!(sender, plain)
    assert ITB.decrypt_stream_one_shot!(receiver, wire) == plain
    :ok = ITB.free(receiver)
    :ok = ITB.free(sender)
    assert_raise ITB.Error, fn -> ITB.encrypt_stream_one_shot!(sender, plain) end
  end

  test "empty payload is rejected with bad_input" do
    # Go core rejects zero-length plaintext uniformly with
    # ErrEmptyInput -> :bad_input before any wire is produced.
    for profile <- ["streaming-aead-triple-mac-v1", "streaming-noaead-triple-v1"] do
      {:ok, sender} = ITB.init(profile)
      assert {:error, {:bad_input, _}} = ITB.encrypt_stream_one_shot(sender, <<>>)
      :ok = ITB.free(sender)
    end
  end

  # Probes successive flip positions until one is rejected; false
  # only if the whole wire is exhausted.
  defp probe_flip(receiver, wire, pos) do
    cond do
      pos >= byte_size(wire) ->
        false

      match?({:error, _}, ITB.decrypt_stream_one_shot(receiver, flip_byte(wire, pos))) ->
        true

      true ->
        probe_flip(receiver, wire, pos + 1)
    end
  end
end
