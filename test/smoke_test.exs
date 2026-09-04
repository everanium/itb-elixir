defmodule ITB.SmokeTest do
  # Init -> save -> load -> encrypt_message -> decrypt_message round
  # trip on the MAC Single Message profile, plus version / runtime
  # knobs, the rekey rotation path, persistence, and the
  # profile catalogue.
  use ExUnit.Case

  test "smoke round trip" do
    {:ok, sender} = ITB.init("singlemsg-triple-mac-v1")
    {:ok, blob} = ITB.save(sender)
    assert byte_size(blob) > 0

    {:ok, receiver} = ITB.load(blob)

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
    receiver = ITB.load!(ITB.save!(sender))
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

  test "save / load round trip" do
    {:ok, sender} = ITB.init("singlemsg-triple-mac-v1")
    {:ok, blob} = ITB.save(sender)
    assert {:ok, blob} == ITB.save(sender)
    {:ok, receiver} = ITB.load(blob)
    assert {:ok, blob} == ITB.save(receiver)
    {:ok, wire} = ITB.encrypt_message(sender, "in-memory persist")
    assert {:ok, "in-memory persist"} == ITB.decrypt_message(receiver, wire)
    :ok = ITB.free(receiver)
    :ok = ITB.free(sender)
  end

  test "save_f / load_f round trip" do
    dir = Path.join(System.tmp_dir!(), "itb-elixir-persist-#{System.unique_integer([:positive])}")
    File.mkdir_p!(dir)
    path = Path.join(dir, "session.blob")

    try do
      {:ok, sender} = ITB.init("singlemsg-triple-mac-v1")
      :ok = ITB.save_f(sender, path)
      assert Bitwise.band(File.stat!(path).mode, 0o777) == 0o600
      {:ok, receiver} = ITB.load_f(path)
      assert ITB.save(sender) == ITB.save(receiver)
      {:ok, wire} = ITB.encrypt_message(sender, "file persist")
      assert {:ok, "file persist"} == ITB.decrypt_message(receiver, wire)
      assert {:error, {:bad_input, _}} = ITB.load_f(Path.join(dir, "absent.blob"))
      :ok = ITB.free(receiver)
      :ok = ITB.free(sender)
    after
      File.rm_rf!(dir)
    end
  end

  test "load with master override" do
    {:ok, sender} = ITB.init("singlemsg-triple-mac-v1")
    perm = :binary.copy(<<0x31>>, 32)
    wrap = :binary.copy(<<0x32>>, 32)
    {:ok, rotated} = ITB.rekey(sender, perm, wrap)
    {:ok, blob} = ITB.save(sender)
    {:ok, receiver} = ITB.load(blob, perm, wrap)
    assert {:ok, rotated} == ITB.save(receiver)
    {:ok, wire} = ITB.encrypt_message(sender, "master override")
    assert {:ok, "master override"} == ITB.decrypt_message(receiver, wire)
    :ok = ITB.free(receiver)
    :ok = ITB.free(sender)
  end

  test "inspect / lookup / profiles" do
    {:ok, pipe} = ITB.init("singlemsg-triple-mac-v1")
    {:ok, blob} = ITB.save(pipe)
    :ok = ITB.free(pipe)
    {:ok, record} = ITB.inspect(blob)
    assert record["name"] == "singlemsg-triple-mac-v1"
    assert record["mode"] == "singlemsg-mac"
    assert record["keybits"] > 0
    assert {:ok, record} == ITB.lookup("singlemsg-triple-mac-v1")
    assert {:error, {:bad_input, _}} = ITB.inspect("not a blob")
    assert {:error, {:unknown_profile, _}} = ITB.lookup("no-such-profile")
    names = ITB.profiles()
    assert "singlemsg-triple-mac-v1" in names
    assert names == Enum.sort(names)
    for name <- names, do: assert(ITB.lookup!(name)["name"] == name)
  end

  test "max_workers" do
    {:ok, pipe} = ITB.init("singlemsg-triple-mac-v1")
    :ok = ITB.max_workers(pipe, 2)
    # Clamped to auto / 256, never rejected.
    :ok = ITB.max_workers(pipe, -1)
    :ok = ITB.max_workers(pipe, 10_000)
    {:ok, wire} = ITB.encrypt_message(pipe, "after cap change")
    assert {:ok, "after cap change"} == ITB.decrypt_message(pipe, wire)
    :ok = ITB.free(pipe)
    # A negative init-time cap is clamped as well.
    {:ok, neg} = ITB.init("singlemsg-triple-mac-v1", %{maxWorkers: -1})
    {:ok, w2} = ITB.encrypt_message(neg, "negative cap")
    assert {:ok, "negative cap"} == ITB.decrypt_message(neg, w2)
    :ok = ITB.free(neg)
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
    {:ok, before_blob} = ITB.save(sender)

    perm = :binary.copy(<<0x11>>, 32)
    wrap = :binary.copy(<<0x22>>, 32)
    {:ok, after_blob} = ITB.rekey(sender, perm, wrap)
    refute after_blob == before_blob
    assert {:ok, after_blob} == ITB.save(sender)

    {:ok, receiver} = ITB.load(after_blob)
    plain = "post-rekey payload"
    {:ok, wire} = ITB.encrypt_message(sender, plain)
    {:ok, back} = ITB.decrypt_message(receiver, wire)
    assert back == plain

    :ok = ITB.free(receiver)
    :ok = ITB.free(sender)
  end
end
