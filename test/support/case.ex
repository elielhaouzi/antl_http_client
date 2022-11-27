defmodule AntlHttpClientTest.Case do
  @moduledoc false

  use ExUnit.CaseTemplate

  using do
    quote do
      import AntlHttpClientTest.Case

      def headers(), do: %{"content-type" => "application/json"}
      def base_url(), do: "http://localhost:12345"
    end
  end

  setup_all do
    start_supervised!(
      AntlHttpClient.secure_finch_child_spec(SecureFinch,
        certfile: Path.absname("ssl/certificate.pem", __DIR__),
        keyfile: Path.absname("ssl/key.pem", __DIR__)
      )
    )

    start_supervised!(AntlHttpClient.insecure_finch_child_spec(InsecureFinch))

    :ok
  end

  setup do
    bypass = Bypass.open(port: 12345)

    {:ok, bypass: bypass}
  end
end
