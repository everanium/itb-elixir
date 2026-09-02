defmodule ItbElixir.MixProject do
  use Mix.Project

  # ITB Elixir binding — thin proxy over the Erlang binding's `itb`
  # module via native BEAM bytecode interop (zero FFI hop of its own).
  # The Erlang binding (bindings/erlang) is consumed as a rebar3 path
  # dependency; its NIF shim carries the only native code in the BEAM
  # stack. No ITB construction logic lives in this binding.

  def project do
    [
      app: :itb_elixir,
      version: "0.3.4",
      elixir: "~> 1.17",
      elixirc_paths: elixirc_paths(Mix.env()),
      start_permanent: false,
      deps: deps(),
      description:
        "ITB Elixir binding - thin proxy over the ITB Erlang binding " <>
          "via BEAM bytecode interop"
    ]
  end

  def application do
    [extra_applications: []]
  end

  defp elixirc_paths(:test), do: ["lib", "test/support"]
  defp elixirc_paths(_), do: ["lib"]

  defp deps do
    [
      # The Erlang binding is the backend: a standard OTP application
      # built by rebar3 (its compile pre-hook builds the NIF shim; the
      # shim links the C binding's static archive plus libitb.so with
      # an embedded RPATH). ./build.sh builds libitb.so and the C
      # archive before Mix compiles this dependency.
      {:itb, path: "../erlang", manager: :rebar3}
    ]
  end
end
