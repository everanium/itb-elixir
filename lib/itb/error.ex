defmodule ITB.Error do
  @moduledoc """
  Exception raised by the `ITB` bang variants and the lazy
  `ITB.Stream` adapters.

  Carries the same `{status, detail}` pair the tuple-returning
  surface reports: `status` is an `ITB.Status.t()` atom, `detail`
  the Go-side diagnostic binary.
  """

  defexception [:status, :detail]

  @type t :: %__MODULE__{status: ITB.Status.t(), detail: binary()}

  @impl true
  def exception({status, detail}) when is_atom(status) and is_binary(detail) do
    %__MODULE__{status: status, detail: detail}
  end

  @impl true
  def message(%__MODULE__{status: status, detail: <<>>}), do: Atom.to_string(status)

  def message(%__MODULE__{status: status, detail: detail}) do
    "#{status}: #{detail}"
  end
end
