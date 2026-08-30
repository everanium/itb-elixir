defmodule ITB.StreamIncrementalTest do
  # Explicit write / end / read round trip with pathological batch
  # sizes (17-byte feed, 23-byte drain) across multiple chunks, and
  # end-of-input semantics.
  use ExUnit.Case

  import ITBTest.Util, only: [pair: 2, pump: 5]

  test "pathological batch sizes across chunks" do
    # Small chunk size so the 64 KiB payload spans many chunks.
    {sender, receiver} = pair("streaming-aead-triple-mac-v1", %{chunkSize: 4096})

    plain = for i <- 0..65_535, into: <<>>, do: <<rem(i, 241)>>

    wire = pump(sender, :encrypt, plain, 17, 23)
    back = pump(receiver, :decrypt, wire, 17, 23)
    assert back == plain

    :ok = ITB.free(receiver)
    :ok = ITB.free(sender)
  end

  test "end is idempotent; write after end fails with bad_input" do
    {:ok, pipe} = ITB.init("streaming-aead-triple-mac-v1")
    {:ok, session} = ITB.encrypt_stream(pipe)
    :ok = ITB.stream_write(session, "payload")
    :ok = ITB.stream_end(session)
    :ok = ITB.stream_end(session)
    assert {:error, {:bad_input, _}} = ITB.stream_write(session, "late")
    :ok = ITB.stream_free(session)
    :ok = ITB.free(pipe)
  end
end
