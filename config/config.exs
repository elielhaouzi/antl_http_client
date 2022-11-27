import Config

if(Mix.env() == :test) do
  config :antl_http_client,
    logger: :app_recorder

  config :app_recorder,
    repo: AntlUtilsEcto.TestRepo
end
