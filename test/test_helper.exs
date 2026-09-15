# Multi-megabyte cipher calls run on dirty schedulers Go-side; give
# every test a generous ceiling instead of ExUnit's 60 s default.
{:ok, _} = Application.ensure_all_started(:crypto)
ExUnit.start(timeout: 600_000)
