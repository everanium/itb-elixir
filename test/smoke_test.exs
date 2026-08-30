defmodule ITB.SmokeTest do
  # Init -> blob -> open -> encrypt_message -> decrypt_message round
  # trip on the MAC Single Message profile, plus version / hashes /
  # runtime knobs and the rekey rotation path.
  use ExUnit.Case

  test "smoke round trip" do
    {:ok, sender} = ITB.init("singlemsg-triple-mac-v1")
    {:ok, blob} = ITB.blob(sender)
    assert byte_size(blob) > 0

    {:ok, receiver} = ITB.open("singlemsg-triple-mac-v1", blob)

    plain = "smoke round-trip payload"
    {:ok, wire} = ITB.encrypt_message(sender, plain)
    refute wire == plain

    {:ok, back} = ITB.decrypt_message(receiver, wire)
    assert back == plain

    :ok = ITB.free(receiver)
    :ok = ITB.free(sender)
  end

  test "bang variants round trip" do
    sender = ITB.init!("singlemsg-triple-mac-v1")
    receiver = ITB.open!("singlemsg-triple-mac-v1", ITB.blob!(sender))
    wire = ITB.encrypt_message!(sender, "bang payload")
    assert ITB.decrypt_message!(receiver, wire) == "bang payload"
    :ok = ITB.free(receiver)
    :ok = ITB.free(sender)
  end

  test "version" do
    {:ok, version} = ITB.version()
    assert byte_size(version) > 0
    assert ITB.version!() == version
  end

  test "hashes roster" do
    hashes = ITB.hashes()
    assert length(hashes) > 0

    for {name, width} <- hashes do
      assert is_binary(name) and byte_size(name) > 0
      assert is_integer(width) and width > 0
    end
  end

  test "runtime knobs query without changing" do
    # Negative values query without changing; the return is the
    # previous setting.
    prev = ITB.set_memory_limit(-1)
    assert is_integer(prev)
    assert ITB.set_memory_limit(-1) == prev
    prev_gc = ITB.set_gc_percent(-2)
    assert is_integer(prev_gc)
  end

  test "rekey rotates the blob and the receiver follows" do
    {:ok, sender} = ITB.init("singlemsg-triple-mac-v1")
    {:ok, before_blob} = ITB.blob(sender)

    perm = :binary.copy(<<0x11>>, 32)
    wrap = :binary.copy(<<0x22>>, 32)
    :ok = ITB.rekey(sender, perm, wrap)

    {:ok, after_blob} = ITB.blob(sender)
    refute after_blob == before_blob

    {:ok, receiver} = ITB.open("singlemsg-triple-mac-v1", after_blob)
    plain = "post-rekey payload"
    {:ok, wire} = ITB.encrypt_message(sender, plain)
    {:ok, back} = ITB.decrypt_message(receiver, wire)
    assert back == plain

    :ok = ITB.free(receiver)
    :ok = ITB.free(sender)
  end
end
