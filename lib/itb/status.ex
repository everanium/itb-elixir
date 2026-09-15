defmodule ITB.Status do
  @moduledoc """
  Status atoms of the ITB error surface.

  Every failing call returns `{:error, {status, detail}}` where
  `status` is one of the atoms below — mirroring the C binding's
  status table through the Erlang binding unchanged — and `detail`
  is the Go-side diagnostic binary fetched immediately after the
  failing call. The atom is always attributable to the call that
  received it; the detail text comes from a process-global
  last-write-wins store on the Go side, so under concurrent use it
  may belong to a different call.
  """

  @type t ::
          :bad_hash
          | :bad_key_bits
          | :bad_handle
          | :bad_input
          | :buffer_too_small
          | :encrypt_failed
          | :decrypt_failed
          | :seed_width_mix
          | :bad_mac
          | :mac_failure
          | :blob_malformed_recipe
          | :recipe_primitive_unknown
          | :unknown_profile
          | :blob_mode_mismatch
          | :blob_malformed
          | :blob_version_too_new
          | :blob_too_many_opts
          | :stream_truncated
          | :stream_after_final
          | :triple_closed
          | :profile_exists
          | :internal

  @statuses [
    :bad_hash,
    :bad_key_bits,
    :bad_handle,
    :bad_input,
    :buffer_too_small,
    :encrypt_failed,
    :decrypt_failed,
    :seed_width_mix,
    :bad_mac,
    :mac_failure,
    :blob_malformed_recipe,
    :recipe_primitive_unknown,
    :unknown_profile,
    :blob_mode_mismatch,
    :blob_malformed,
    :blob_version_too_new,
    :blob_too_many_opts,
    :stream_truncated,
    :stream_after_final,
    :triple_closed,
    :profile_exists,
    :internal
  ]

  @doc """
  The status atoms an error tuple may carry.
  """
  @spec known() :: [t()]
  def known, do: @statuses
end
