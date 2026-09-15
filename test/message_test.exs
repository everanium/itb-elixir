defmodule ITB.MessageTest do
  # Single Message round trips across shipped profiles and payload
  # shapes (empty, 1 byte, structured, CSPRNG-filled), wire
  # uniqueness, and opts pass-through in both map and keyword form.
  use ExUnit.Case

  import ITBTest.Util, only: [pair: 2]

  defp round_trips(profile) do
    {sender, receiver} = pair(profile, %{})

    payloads = [
      <<0>>,
      "any text or binary data",
      :binary.copy(<<0x00>>, 4096),
      :binary.copy(<<0xFF>>, 4096),
      :crypto.strong_rand_bytes(100_000)
    ]

    for plain <- payloads do
      {:ok, wire} = ITB.encrypt_message(sender, plain)
      assert wire != plain
      {:ok, back} = ITB.decrypt_message(receiver, wire)
      assert back == plain
    end

    :ok = ITB.free(receiver)
    :ok = ITB.free(sender)
  end

  test "MAC profile round trips", do: round_trips("singlemsg-triple-mac-v1")

  test "No MAC profile round trips", do: round_trips("singlemsg-triple-nomac-v1")

  test "wire uniqueness across encryptions" do
    # Two encryptions of the same plaintext must produce different
    # wires (fresh nonce per message).
    {:ok, sender} = ITB.init("singlemsg-triple-nomac-v1")
    plain = :crypto.strong_rand_bytes(4096)
    {:ok, wire1} = ITB.encrypt_message(sender, plain)
    {:ok, wire2} = ITB.encrypt_message(sender, plain)
    refute wire1 == wire2
    :ok = ITB.free(sender)
  end

  test "opts pass-through as a map" do
    # An explicit keyBits / nonceBits pair reaches Go and the round
    # trip still holds.
    opts = %{keyBits: 1024, nonceBits: 512}
    {sender, receiver} = pair("singlemsg-triple-mac-v1", opts)
    plain = :crypto.strong_rand_bytes(8192)
    {:ok, wire} = ITB.encrypt_message(sender, plain)
    {:ok, back} = ITB.decrypt_message(receiver, wire)
    assert back == plain
    :ok = ITB.free(receiver)
    :ok = ITB.free(sender)
  end

  test "opts pass-through as a keyword list" do
    opts = [keyBits: 1024, nonceBits: 512]
    {sender, receiver} = pair("singlemsg-triple-mac-v1", opts)
    plain = :crypto.strong_rand_bytes(8192)
    {:ok, wire} = ITB.encrypt_message(sender, plain)
    {:ok, back} = ITB.decrypt_message(receiver, wire)
    assert back == plain
    :ok = ITB.free(receiver)
    :ok = ITB.free(sender)
  end

  test "empty payload is rejected with bad_input" do
    # Go core rejects zero-length plaintext uniformly with
    # ErrEmptyInput -> :bad_input before any wire is produced. An
    # empty message has no cover story: it is always distinguishable
    # at some layer (wire length, timing, traffic count). Callers for
    # whom an empty signal is meaningful send a marker byte instead.
    for profile <- ["singlemsg-triple-mac-v1", "singlemsg-triple-nomac-v1"] do
      {:ok, sender} = ITB.init(profile)
      assert {:error, {:bad_input, _}} = ITB.encrypt_message(sender, <<>>)
      :ok = ITB.free(sender)
    end
  end
end
