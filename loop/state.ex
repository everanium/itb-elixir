defmodule Loop.Config do
  @moduledoc """
  The resolved command line. Shapes are `:stream` / `:message` /
  `:stream_one_shot` / `:both`; payload modes `:fixed` / `:rotating` /
  `:pattern_zero` / `:pattern_ff` / `:pattern_ascii`.
  """

  defstruct duration_ns: 0,
            iterations: 0,
            workers_requested: 0,
            workers: 0,
            shape: :stream,
            hash: "",
            mac: "",
            payload: 0,
            memlimit: 0,
            memlimit_auto: false,
            gogc: 0,
            parallax: true,
            wrapper: true,
            profile: "",
            key_bits: 0,
            nonce_bits: 0,
            blob_mode: 1,
            chunk_size: 0,
            barrier_fill: 0,
            drbg: "",
            gomaxprocs: 0,
            rekey_every: 0,
            blob_cycle_every: 0,
            payload_mode: :fixed,
            seed: 0,
            json_output: false,
            memprofile: ""
end

defmodule Loop.WStats do
  @moduledoc """
  What one worker hands back when it returns: its counters, the
  instant it finished, and the error it stopped on.
  """

  defstruct id: 0,
            iters: 0,
            bytes_enc: 0,
            bytes_dec: 0,
            nanos_enc: 0,
            nanos_dec: 0,
            finish_ns: 0,
            failed: false,
            error: ""
end

defmodule Loop.Run do
  @moduledoc """
  The run handle every worker carries: the resolved configuration, the
  pid of the state process that owns the Pipeline handles and the
  lock, the atomics word holding the stop request, the counters array
  behind the rekey and blob-cycle totals, and the two profile names
  the log lines quote.
  """

  defstruct [:cfg, :state, :flags, :counts, stream_profile: "", msg_profile: ""]
end

defmodule Loop.State do
  @moduledoc """
  The state every worker shares: the Pipeline handles, the retained
  blobs, the reader / writer lock that keeps iterations clear of
  handle mutation, the stop request, and the rekey and blob-cycle
  totals.

  Elixir-specific. BEAM has no reader / writer lock primitive, so the
  lock is a process that owns the handles and hands them out: a reader
  is granted immediately unless a writer holds or is waiting, a writer
  waits until the last reader has left. The handles travel with the
  grant rather than being cached by the worker, because a blob reopen
  frees the running handle and swaps a fresh one in — a worker holding
  the term from launch would be calling into a released resource from
  the first cycle onwards. The lock holder is monitored, so a worker
  that dies holding either side releases it instead of wedging the
  run.
  """

  # Slot 1 of the atomics word carries the stop request; slots 1 and 2
  # of the counters array carry the rekey and blob-cycle totals.
  @slot_stop 1
  @count_rekeys 1
  @count_blob_cycles 2

  defmodule S do
    @moduledoc false
    defstruct [
      :stream_pipe,
      :msg_pipe,
      stream_blob: <<>>,
      msg_blob: <<>>,
      readers: [],
      writer: :none,
      wait_readers: [],
      wait_writers: [],
      monitors: %{}
    ]
  end

  # ------------------------------------------------------------------
  # Stop request and counters — lock-free, so a worker's per-iteration
  # check never queues behind the lock process.
  # ------------------------------------------------------------------

  def new_flags, do: :atomics.new(1, signed: false)
  def request_stop(flags), do: :atomics.put(flags, @slot_stop, 1)
  def stop_requested?(flags), do: :atomics.get(flags, @slot_stop) == 1

  def new_counts, do: :counters.new(2, [:write_concurrency])

  def bump(counts, :rekeys) do
    :counters.add(counts, @count_rekeys, 1)
    :counters.get(counts, @count_rekeys)
  end

  def bump(counts, :blob_cycles) do
    :counters.add(counts, @count_blob_cycles, 1)
    :counters.get(counts, @count_blob_cycles)
  end

  def count(counts, :rekeys), do: :counters.get(counts, @count_rekeys)
  def count(counts, :blob_cycles), do: :counters.get(counts, @count_blob_cycles)

  # ------------------------------------------------------------------
  # The lock process
  # ------------------------------------------------------------------

  def start(stream_pipe, msg_pipe, stream_blob, msg_blob) do
    spawn_link(fn ->
      loop(%S{
        stream_pipe: stream_pipe,
        msg_pipe: msg_pipe,
        stream_blob: stream_blob,
        msg_blob: msg_blob
      })
    end)
  end

  def stop_process(pid) do
    send(pid, {:shutdown, self()})

    receive do
      {:shutdown_ok, ^pid} -> :ok
    after
      5000 -> :ok
    end
  end

  @doc """
  Grants the read side and hands back the handles in force at that
  instant. Cipher calls run in the caller, not here: routing them
  through this process would serialise every worker and remove the
  shared-handle property the harness exists to exercise.
  """
  def read_lock(pid), do: call(pid, :read_lock)

  def read_unlock(pid) do
    send(pid, {:read_unlock, self()})
    :ok
  end

  def write_lock(pid), do: call(pid, :write_lock)

  @doc """
  Releases the write side, installing whatever the maintenance
  produced. `updates` is a map of the fields that changed.
  """
  def write_unlock(pid, updates) do
    send(pid, {:write_unlock, self(), updates})
    :ok
  end

  @doc """
  The handles without taking the lock, for the shutdown path after
  every worker has returned.
  """
  def handles(pid), do: call(pid, :handles)

  defp call(pid, request) do
    ref = make_ref()
    send(pid, {request, self(), ref})

    receive do
      {^ref, reply} -> reply
    end
  end

  # ------------------------------------------------------------------

  defp loop(st) do
    receive do
      {:read_lock, pid, ref} ->
        loop(request_read(st, pid, ref))

      {:write_lock, pid, ref} ->
        loop(request_write(st, pid, ref))

      {:read_unlock, pid} ->
        loop(grant(release_reader(st, pid)))

      {:write_unlock, pid, updates} ->
        loop(grant(release_writer(apply_updates(st, updates), pid)))

      {:handles, pid, ref} ->
        send(pid, {ref, {st.stream_pipe, st.msg_pipe}})
        loop(st)

      # A holder that died never sends its unlock; drop its claim so
      # the run can finish instead of wedging.
      {:DOWN, _ref, :process, pid, _reason} ->
        loop(grant(release_writer(release_reader(st, pid), pid)))

      {:shutdown, pid} ->
        send(pid, {:shutdown_ok, self()})
        :ok
    end
  end

  defp request_read(%S{writer: :none, wait_writers: []} = st, pid, ref) do
    send(pid, {ref, {st.stream_pipe, st.msg_pipe}})
    watch(%{st | readers: [pid | st.readers]}, pid)
  end

  defp request_read(st, pid, ref),
    do: %{st | wait_readers: st.wait_readers ++ [{pid, ref}]}

  defp request_write(%S{writer: :none, readers: []} = st, pid, ref) do
    send(pid, {ref, {st.stream_pipe, st.msg_pipe, st.stream_blob, st.msg_blob}})
    watch(%{st | writer: pid}, pid)
  end

  defp request_write(st, pid, ref),
    do: %{st | wait_writers: st.wait_writers ++ [{pid, ref}]}

  # Writer preference: a queued writer goes first, so a steady stream
  # of iterations cannot starve a rekey that is already waiting.
  defp grant(%S{writer: :none, readers: [], wait_writers: [{pid, ref} | rest]} = st) do
    send(pid, {ref, {st.stream_pipe, st.msg_pipe, st.stream_blob, st.msg_blob}})
    watch(%{st | writer: pid, wait_writers: rest}, pid)
  end

  defp grant(%S{writer: :none, wait_writers: [], wait_readers: [_ | _] = waiting} = st) do
    Enum.each(waiting, fn {pid, ref} ->
      send(pid, {ref, {st.stream_pipe, st.msg_pipe}})
    end)

    Enum.reduce(waiting, %{st | readers: Enum.map(waiting, &elem(&1, 0)) ++ st.readers,
                                wait_readers: []}, fn {pid, _}, acc -> watch(acc, pid) end)
  end

  defp grant(st), do: st

  defp release_reader(st, pid) do
    if pid in st.readers do
      unwatch(%{st | readers: List.delete(st.readers, pid)}, pid)
    else
      st
    end
  end

  defp release_writer(%S{writer: pid} = st, pid), do: unwatch(%{st | writer: :none}, pid)
  defp release_writer(st, _pid), do: st

  defp apply_updates(st, updates), do: struct(st, updates)

  defp watch(st, pid) do
    if Map.has_key?(st.monitors, pid) do
      st
    else
      %{st | monitors: Map.put(st.monitors, pid, Process.monitor(pid))}
    end
  end

  defp unwatch(st, pid) do
    if st.writer == pid or pid in st.readers do
      st
    else
      case Map.pop(st.monitors, pid) do
        {nil, _} ->
          st

        {ref, rest} ->
          Process.demonitor(ref, [:flush])
          %{st | monitors: rest}
      end
    end
  end
end
