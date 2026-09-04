defmodule ITB.ErrorsTest do
  # Error-mapping surface: opaque-string relay, unknown profile,
  # tampered-wire MAC failure, freed-handle paths, bang-variant
  # raises, profile registration from a JSON record (with an 8-entry
  # `hashes` constellation), duplicate registration.
  use ExUnit.Case

  import ITBTest.Util, only: [pair: 2, flip_byte: 2]

  test "unknown profile" do
    {:error, {:unknown_profile, detail}} = ITB.init("no-such-profile")
    assert byte_size(detail) > 0
  end

  test "unknown opts key" do
    # Typoed lowercase s — the binding performs no key validation of
    # its own; Go rejects the unknown key.
    assert {:error, {:bad_input, _}} =
             ITB.init("singlemsg-triple-mac-v1", %{chunksize: 4096})
  end

  test "unknown inner hash" do
    # An unknown inner-hash name is relayed to Go and rejected there.
    assert {:error, _} =
             ITB.init("singlemsg-triple-mac-v1", %{innerHash: "no-such-hash"})
  end

  test "malformed blob" do
    assert {:error, _} = ITB.load("not a session blob")
  end

  test "bang variant raises ITB.Error" do
    err = assert_raise ITB.Error, fn -> ITB.init!("no-such-profile") end
    assert err.status == :unknown_profile
    assert byte_size(err.detail) > 0
    assert Exception.message(err) =~ "unknown_profile"
    assert err.status in ITB.Status.known()
  end

  test "tampered message fails with mac_failure" do
    # A bit flip in authenticated wire content fails with
    # mac_failure. A single flip can land in the container's CSPRNG
    # residue — where the decrypt legitimately completes clean — so
    # successive flip positions are probed until one lands in
    # authenticated content.
    {sender, receiver} = pair("singlemsg-triple-mac-v1", %{})
    plain = :crypto.strong_rand_bytes(4096)
    {:ok, wire} = ITB.encrypt_message(sender, plain)
    assert probe_flip(receiver, wire, 0)
    :ok = ITB.free(receiver)
    :ok = ITB.free(sender)
  end

  defp probe_flip(_receiver, wire, pos) when pos >= byte_size(wire), do: false

  defp probe_flip(receiver, wire, pos) do
    tampered = flip_byte(wire, pos)

    case ITB.decrypt_message(receiver, tampered) do
      {:error, {:mac_failure, _}} ->
        true

      {:ok, _} ->
        # Flip landed in unauthenticated residue — next position.
        probe_flip(receiver, wire, pos + 1)

      {:error, {_, _}} ->
        # A flip in the envelope framing may fail structurally
        # before MAC verification; keep probing for a MAC hit.
        probe_flip(receiver, wire, pos + 1)
    end
  end

  test "freed pipeline paths" do
    {:ok, pipe} = ITB.init("singlemsg-triple-mac-v1")
    :ok = ITB.free(pipe)
    # Idempotent.
    :ok = ITB.free(pipe)
    assert {:error, {:bad_handle, _}} = ITB.encrypt_message(pipe, "x")
    assert {:error, {:bad_handle, _}} = ITB.save(pipe)
    assert {:error, {:bad_handle, _}} = ITB.encrypt_stream(pipe)
  end

  test "freed stream paths" do
    {:ok, pipe} = ITB.init("streaming-aead-triple-mac-v1")
    {:ok, session} = ITB.encrypt_stream(pipe)
    :ok = ITB.stream_free(session)
    # Idempotent.
    :ok = ITB.stream_free(session)
    assert {:error, {:bad_handle, _}} = ITB.stream_write(session, "x")
    assert {:error, {:bad_handle, _}} = ITB.stream_end(session)
    assert {:error, {:bad_handle, _}} = ITB.stream_read(session, 16)
    :ok = ITB.free(pipe)
  end

  test "badarg on non-handle terms" do
    assert_raise ArgumentError, fn -> ITB.encrypt_message(make_ref(), "x") end
    assert_raise ArgumentError, fn -> ITB.stream_write(make_ref(), "x") end
    assert_raise FunctionClauseError, fn -> ITB.init("p", :not_opts) end
  end

  test "register round trip and duplicate rejection" do
    # Register with an 8-entry width-256 hashes constellation, layers
    # off; the registered profile round-trips, is visible in the
    # catalogue, and a duplicate registration fails with
    # profile_exists.
    hashes = ~w(blake3 blake2s areion256 blake2b256 chacha20 blake3 blake2s areion256)

    profile = %{
      mode: "singlemsg-nomac",
      width: 256,
      hashes: hashes,
      keybits: 1024,
      parallax: false,
      wrapper: false
    }

    :ok = ITB.register("elixir-binding-test-mixed", profile)
    assert "elixir-binding-test-mixed" in ITB.profiles()
    assert ITB.lookup!("elixir-binding-test-mixed")["hashes"] == hashes

    assert {:error, {:profile_exists, _}} =
             ITB.register("elixir-binding-test-mixed", profile)

    # Strict record decode on the Go side: an unknown key is rejected
    # there, not by the binding.
    assert {:error, {:bad_input, _}} =
             ITB.register("elixir-binding-test-badkey", ~s({"mode":"singlemsg-nomac","bogus":1}))

    {sender, receiver} = pair("elixir-binding-test-mixed", %{})
    plain = :crypto.strong_rand_bytes(8192)
    {:ok, wire} = ITB.encrypt_message(sender, plain)
    {:ok, back} = ITB.decrypt_message(receiver, wire)
    assert back == plain
    :ok = ITB.free(receiver)
    :ok = ITB.free(sender)
  end
end
