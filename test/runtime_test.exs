defmodule ITB.RuntimeTest do
  @moduledoc """
  The runtime-shaping knobs and the hash-registry enumeration: the
  GOMAXPROCS setter and its query form, the heap-profile writer on a
  good and on a rejected path, the pool-counter vector and its length
  query, and the registry names `ITB.init/2` accepts under
  `innerHash`. Every entry delegates to the Erlang binding's `itb3`
  module — `:itb3.set_gomaxprocs/1`, `:itb3.write_heap_profile/1`,
  `:itb3.pool_stats_len/0`, `:itb3.pool_stats/0`, `:itb3.hash_names/0`.
  """
  use ExUnit.Case, async: false

  # Zero or a negative value queries without changing, so the query is
  # repeatable and the round trip restores what was in force.
  test "set_gomaxprocs queries and sets" do
    before = ITB.set_gomaxprocs(0)
    assert before > 0
    assert ITB.set_gomaxprocs(0) == before
    assert ITB.set_gomaxprocs(2) == before
    assert ITB.set_gomaxprocs(0) == 2
    assert ITB.set_gomaxprocs(before) == 2
    assert ITB.set_gomaxprocs(0) == before
  end

  test "write_heap_profile writes a non-empty profile" do
    path = Path.join(System.tmp_dir!(), "itb-elixir-heap.pprof")
    assert :ok = ITB.write_heap_profile(path)
    assert File.stat!(path).size > 0
    File.rm!(path)
  end

  # A path that cannot be created is rejected, and the diagnostic the
  # library composed comes back with the status atom.
  test "write_heap_profile rejects an uncreatable path" do
    bad = Path.join([System.tmp_dir!(), "no-such-directory", "heap.pprof"])
    assert {:error, {:bad_input, detail}} = ITB.write_heap_profile(bad)
    assert byte_size(detail) > 0
  end

  # The slot count is read from the library, and the vector it fills
  # matches that count; slot 0 carries the tier count and the layout
  # 1 + 5*t + 8 follows from it.
  test "pool_stats fills exactly the slots the length query reports" do
    len = ITB.pool_stats_len()
    assert len > 0
    assert {:ok, slots} = ITB.pool_stats()
    assert length(slots) == len
    [tiers | _] = slots
    assert tiers > 0
    assert len == 1 + 5 * tiers + 8
    assert Enum.all?(slots, &(is_integer(&1) and &1 >= 0))
  end

  # The counters are monotonic totals since library load, so a cipher
  # call between two snapshots can only move them upward.
  test "pool counters never move downward across a cipher call" do
    {:ok, before} = ITB.pool_stats()
    {:ok, pipe} = ITB.init("singlemsg-triple-mac-v1")
    {:ok, _wire} = ITB.encrypt_message(pipe, :binary.copy("x", 65_536))
    :ok = ITB.free(pipe)
    {:ok, later} = ITB.pool_stats()
    assert length(before) == length(later)
    assert Enum.all?(Enum.zip(before, later), fn {a, b} -> b >= a end)
  end

  # Every registry name is accepted as an inner hash, which is what
  # makes the enumeration usable for validating a primitive name.
  test "every hash_names entry is a usable inner hash" do
    names = ITB.hash_names()
    assert names != []
    assert Enum.all?(names, &is_binary/1)
    assert "areion512" in names
    assert Enum.uniq(names) == names

    Enum.each(names, fn name ->
      {:ok, pipe} = ITB.init("singlemsg-triple-nomac-v1", %{innerHash: name})
      :ok = ITB.free(pipe)
    end)
  end

  # Every status atom an error tuple can carry resolves to the numeric
  # code the C ABI assigns it, and an atom outside the table resolves
  # to the internal-error code.
  test "status codes mirror the C ABI enum" do
    assert ITB.Status.code(:ok) == 0
    assert ITB.Status.code(:bad_input) == 4
    assert ITB.Status.code(:mac_failure) == 10
    assert ITB.Status.code(:unknown_profile) == 13
    assert ITB.Status.code(:profile_exists) == 26
    assert ITB.Status.code(:internal) == 99
    assert ITB.Status.code(:no_such_status) == 99

    # The codes are distinct, so a diagnostic naming one names it
    # unambiguously.
    codes = Enum.map(ITB.Status.known(), &ITB.Status.code/1)
    assert Enum.uniq(codes) == codes
  end

  # The atom a failing call hands back resolves through the same
  # accessor, so the pair (atom, code) is attributable to one call.
  test "the status of a failing call resolves to its code" do
    assert {:error, {status, _detail}} = ITB.lookup("no-such-profile")
    assert status == :unknown_profile
    assert ITB.Status.code(status) == 13
  end

  test "an unregistered primitive is absent and rejected" do
    refute "no-such-primitive" in ITB.hash_names()

    assert {:error, {_, _}} =
             ITB.init("singlemsg-triple-nomac-v1", %{innerHash: "no-such-primitive"})
  end
end
