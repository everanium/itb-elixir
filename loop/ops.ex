defmodule Loop.Ops do
  @moduledoc """
  The maintenance operations that mutate a live Pipeline handle
  between iterations: master rotation (`--rekey-every`) and blob
  reopen (`--blob-cycle-every`).
  """

  alias Loop.{Payload, Run, State}

  # Byte length of each fresh master drawn for a rotation. Matches the
  # size Init auto-generates for both the parallax and the wrapper
  # master.
  @rekey_master_size 32

  @doc """
  Handle mutation. Runs the periodic Pipeline-mutating operations
  after a completed iteration: master rotation (`--rekey-every`) and
  blob reopen (`--blob-cycle-every`). Both intervals count per-worker
  iterations; the warmup iteration (iter 0) never triggers because the
  worker loop calls this for iter >= 1 only. Rekey rewrites the
  outer-layer keying of a live handle and a blob reopen replaces the
  handle outright; each takes the write lock, so in-flight cipher
  calls on other workers drain before anything changes and no encrypt
  is separated from its decrypt by either.
  """
  @spec maintenance(%Run{}, non_neg_integer(), non_neg_integer()) :: :ok | {:error, String.t()}
  def maintenance(run, id, iter) do
    if due?(run.cfg.rekey_every, iter) do
      case rekey_pipes(run, id, iter) do
        :ok -> blob_stage(run, id, iter)
        {:error, _} = err -> err
      end
    else
      blob_stage(run, id, iter)
    end
  end

  defp blob_stage(run, id, iter) do
    if due?(run.cfg.blob_cycle_every, iter) do
      blob_cycle_pipes(run, id, iter)
    else
      :ok
    end
  end

  defp due?(0, _iter), do: false
  defp due?(every, iter), do: rem(iter, every) == 0

  # Master rotation. Rotates the parallax + wrapper masters on every
  # active Pipeline under the write lock and retains the refreshed blob
  # for subsequent blob reopens. Masters are drawn fresh from the OS
  # CSPRNG on every rotation regardless of `--seed` (master rotation is
  # pipeline keying, not plaintext content); a disabled layer passes no
  # bytes, which Rekey ignores. The eight inner seeds and the MAC key
  # are untouched by design — Rekey targets only the two outer-layer
  # master secrets.
  defp rekey_pipes(run, id, iter) do
    perm = master(run.cfg.parallax)
    wrap = master(run.cfg.wrapper)
    {stream_pipe, msg_pipe, _stream_blob, _msg_blob} = State.write_lock(run.state)

    case rekey_one(stream_pipe, perm, wrap) do
      {:error, status, detail} ->
        State.write_unlock(run.state, %{})
        {:error, op_error(id, iter, "Rekey", run.stream_profile, status, detail)}

      {:ok, stream_update} ->
        case rekey_one(msg_pipe, perm, wrap) do
          {:error, status, detail} ->
            State.write_unlock(run.state, rename(stream_update, :stream_blob))
            {:error, op_error(id, iter, "Rekey", run.msg_profile, status, detail)}

          {:ok, msg_update} ->
            updates =
              Map.merge(rename(stream_update, :stream_blob), rename(msg_update, :msg_blob))

            State.write_unlock(run.state, updates)
            n = State.bump(run.counts, :rekeys)

            Loop.Main.log(
              "rekey: g#{id} iter #{iter} rotated parallax + wrapper masters (rekey ##{n})"
            )

            :ok
        end
    end
  end

  defp master(true), do: Payload.random_bytes(@rekey_master_size)
  defp master(false), do: <<>>

  defp rekey_one(nil, _perm, _wrap), do: {:ok, %{}}

  defp rekey_one(pipe, perm, wrap) do
    case ITB.rekey(pipe, perm, wrap) do
      {:ok, blob} -> {:ok, %{blob: blob}}
      {:error, {status, detail}} -> {:error, status, detail}
    end
  end

  defp rename(update, key) do
    case Map.fetch(update, :blob) do
      {:ok, blob} -> %{key => blob}
      :error -> %{}
    end
  end

  # Blob reopen. Reopens every active Pipeline from its retained blob
  # under the write lock: a fresh handle is loaded from the blob, the
  # running handle is freed, and the fresh one is swapped in, so every
  # later iteration round-trips through seeds and masters that survived
  # a blob crossing. The input is the blob Init or the latest Rekey
  # handed out, not a fresh Save: that is what a receiver holds, and
  # reopening from it proves the handed-out bytes rather than the live
  # state. The blob carries the Pipeline's full shape, so no override
  # reaches the reopen. On a Load failure the running handle stays and
  # the failure aborts the run.
  defp blob_cycle_pipes(run, id, iter) do
    {stream_pipe, msg_pipe, stream_blob, msg_blob} = State.write_lock(run.state)

    case reopen(stream_pipe, stream_blob) do
      {:error, status, detail} ->
        State.write_unlock(run.state, %{})
        {:error, op_error(id, iter, "Load", run.stream_profile, status, detail)}

      {:ok, stream_fresh} ->
        case reopen(msg_pipe, msg_blob) do
          {:error, status, detail} ->
            State.write_unlock(run.state, swap(:stream_pipe, stream_pipe, stream_fresh))
            {:error, op_error(id, iter, "Load", run.msg_profile, status, detail)}

          {:ok, msg_fresh} ->
            updates =
              Map.merge(
                swap(:stream_pipe, stream_pipe, stream_fresh),
                swap(:msg_pipe, msg_pipe, msg_fresh)
              )

            State.write_unlock(run.state, updates)
            n = State.bump(run.counts, :blob_cycles)

            Loop.Main.log(
              "blob-cycle: g#{id} iter #{iter} reopened from session blob (cycle ##{n})"
            )

            :ok
        end
    end
  end

  defp reopen(nil, _blob), do: {:ok, nil}

  defp reopen(_pipe, blob) do
    case ITB.load(blob) do
      {:ok, fresh} -> {:ok, fresh}
      {:error, {status, detail}} -> {:error, status, detail}
    end
  end

  # The running handle is released only once its replacement is in
  # hand, so a failed Load leaves the Pipeline the run is using intact.
  defp swap(_key, _old, nil), do: %{}

  defp swap(key, old, fresh) do
    ITB.free(old)
    %{key => fresh}
  end

  defp op_error(id, iter, op, profile, status, detail) do
    "g#{id} iter #{iter}: #{op}(#{profile}): " <> Loop.Main.status_text(status, detail)
  end
end
