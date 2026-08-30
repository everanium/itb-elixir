defmodule ITB.StreamCancelTest do
  # Freeing an encrypt session mid-flight releases resources cleanly
  # and leaves the Pipeline usable; dropped term references let the
  # resource destructors release as the backstop.
  use ExUnit.Case

  test "cancel mid-flight leaves the Pipeline usable" do
    {:ok, sender} = ITB.init("streaming-aead-triple-mac-v1")

    chunk = :crypto.strong_rand_bytes(100_000)
    {:ok, session} = ITB.encrypt_stream(sender)
    :ok = ITB.stream_write(session, chunk)
    # Freed here without stream_end/1 — stream_free cancels the
    # session.
    :ok = ITB.stream_free(session)

    # The Pipeline stays usable after the cancelled session.
    {:ok, blob} = ITB.blob(sender)
    {:ok, receiver} = ITB.open("streaming-aead-triple-mac-v1", blob)
    plain = "after cancel"
    {:ok, wire} = ITB.encrypt_message(sender, plain)
    {:ok, back} = ITB.decrypt_message(receiver, wire)
    assert back == plain

    :ok = ITB.free(receiver)
    :ok = ITB.free(sender)
  end

  test "garbage collection backstop releases a dropped pair" do
    # Garbage collection releases a dropped mid-flight session +
    # pipeline pair without a crash (the stream resource pins its
    # parent pipeline, so destructor order is safe regardless of
    # collection order).
    :ok = make_and_drop()
    :erlang.garbage_collect()
    Process.sleep(200)

    # The NIF stays fully functional after the collected pair.
    {:ok, pipe} = ITB.init("singlemsg-triple-mac-v1")
    {:ok, wire} = ITB.encrypt_message(pipe, "post-gc")
    assert byte_size(wire) > 0
    :ok = ITB.free(pipe)
  end

  defp make_and_drop do
    {:ok, pipe} = ITB.init("streaming-aead-triple-mac-v1")
    {:ok, session} = ITB.encrypt_stream(pipe)
    :ok = ITB.stream_write(session, "dropped mid-flight")
    :ok
  end
end
