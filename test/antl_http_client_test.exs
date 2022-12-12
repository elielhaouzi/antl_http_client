defmodule AntlHttpClientTest.HttpClientTest do
  use AntlHttpClientTest.Case

  describe "request/4" do
    test "content-type: application/json", %{bypass: bypass} do
      params = %{"data" => "data"}

      Bypass.expect_once(bypass, "POST", "/test", fn conn ->
        assert Plug.Conn.get_req_header(conn, "content-type") == ["application/json"]
        encoded_params = Jason.encode!(params)
        {:ok, ^encoded_params, conn} = conn |> Plug.Conn.read_body()
        Plug.Conn.resp(conn, 200, Jason.encode!(%{"data" => "data"}))
      end)

      assert {:ok, _} =
               AntlHttpClient.request(InsecureFinch, "api_provider", %{
                 method: :post,
                 resource: "#{base_url()}/test",
                 headers: %{"content-type" => "application/json"},
                 body: params
               })
    end

    test "content-type: application/x-www-form-urlencoded", %{bypass: bypass} do
      params = %{"data" => "data"}

      Bypass.expect_once(bypass, "POST", "/test", fn conn ->
        assert Plug.Conn.get_req_header(conn, "content-type") ==
                 ["application/x-www-form-urlencoded"]

        encoded_params = URI.encode_query(params, :rfc3986)
        {:ok, ^encoded_params, conn} = conn |> Plug.Conn.read_body()
        Plug.Conn.resp(conn, 200, Jason.encode!(%{"data" => "data"}))
      end)

      assert {:ok, _} =
               AntlHttpClient.request(InsecureFinch, "api_provider", %{
                 method: :post,
                 resource: "#{base_url()}/test",
                 headers: %{"content-type" => "application/x-www-form-urlencoded"},
                 body: params
               })
    end

    test "bad_request error", %{bypass: bypass} do
      Bypass.expect_once(bypass, "POST", "/test", fn conn ->
        Plug.Conn.resp(conn, 400, Jason.encode!(%{}))
      end)

      assert {:error, {400, %{}}} ==
               AntlHttpClient.request(
                 InsecureFinch,
                 "api_provider",
                 %{method: :post, resource: "#{base_url()}/test", headers: headers(), body: %{}},
                 []
               )
    end

    test "returns the error message if there is one", %{bypass: bypass} do
      Bypass.expect_once(bypass, "POST", "/test", fn conn ->
        Plug.Conn.resp(conn, 403, Jason.encode!(%{"result" => "bad_request"}))
      end)

      assert {:error, {403, %{"result" => "bad_request"}}} ==
               AntlHttpClient.request(
                 InsecureFinch,
                 "api_provider",
                 %{method: :post, resource: "#{base_url()}/test", headers: headers(), body: %{}},
                 []
               )
    end

    test "internal server error", %{bypass: bypass} do
      Bypass.expect_once(bypass, "POST", "/test", fn conn ->
        Plug.Conn.resp(conn, 500, "internal server error")
      end)

      assert {:error, "server_error"} ==
               AntlHttpClient.request(
                 InsecureFinch,
                 "api_provider",
                 %{method: :post, resource: "#{base_url()}/test", headers: headers(), body: %{}},
                 []
               )
    end

    test "connection layer error", %{bypass: bypass} do
      Bypass.down(bypass)

      assert {:error, "connection refused"} =
               AntlHttpClient.request(InsecureFinch, "api_provider", %{
                 method: :post,
                 resource: "#{base_url()}/test",
                 headers: headers(),
                 body: %{}
               })
    end

    test "timeout error", %{bypass: bypass} do
      Bypass.expect_once(bypass, "POST", "/test", fn conn ->
        Process.sleep(5)
        Plug.Conn.resp(conn, 200, Jason.encode!(%{"data" => "data"}))
      end)

      assert {:error, "timeout"} =
               AntlHttpClient.request(
                 InsecureFinch,
                 "api_provider",
                 %{
                   method: :post,
                   resource: "#{base_url()}/test",
                   headers: headers(),
                   body: %{}
                 },
                 receive_timeout: 1
               )

      Bypass.pass(bypass)
    end

    test "when app_recorder is enabled, records outgoing requests with obfuscated_keys obfuscated",
         %{bypass: bypass} do
      params = %{"data" => "data", "secret" => "secret"}
      response = %{"data" => "data", "secret" => "secret"}

      Bypass.expect_once(bypass, "POST", "/test", fn conn ->
        encoded_params = Jason.encode!(params)
        {:ok, ^encoded_params, conn} = conn |> Plug.Conn.read_body()
        Plug.Conn.resp(conn, 200, response |> Jason.encode!())
      end)

      assert {:ok, response} ==
               AntlHttpClient.request(
                 InsecureFinch,
                 "api_provider",
                 %{
                   method: :post,
                   resource: "#{base_url()}/test",
                   headers: %{"authorization" => "token", "content-type" => "application/json"},
                   body: params
                 },
                 logger: :app_recorder
               )

      assert_received {:insert, query}
      assert query.fields[:request_body] == Jason.encode!(params)

      assert_received {:update, query}
      assert query.changes[:response_body] == inspect(response)
    end

    test "recursively obfuscate keys", %{bypass: bypass} do
      params = %{"data" => %{"secret" => "secret"}}
      response = %{"data" => %{"secret" => "secret"}}

      Bypass.expect_once(bypass, "POST", "/test", fn conn ->
        encoded_params = Jason.encode!(params)
        {:ok, ^encoded_params, conn} = conn |> Plug.Conn.read_body()
        Plug.Conn.resp(conn, 200, response |> Jason.encode!())
      end)

      assert {:ok, response} ==
               AntlHttpClient.request(
                 InsecureFinch,
                 "api_provider",
                 %{
                   method: :post,
                   resource: "#{base_url()}/test",
                   headers: %{"authorization" => "token", "content-type" => "application/json"},
                   body: params
                 },
                 obfuscate_keys: ["secret"],
                 logger: :app_recorder
               )

      obfuscated_request_body =
        Jason.encode!(%{"data" => %{"secret" => "se#{String.duplicate("*", 20)}"}})

      assert_received {:insert, query}
      assert query.fields[:request_body] == obfuscated_request_body

      obfuscated_response_body = %{"data" => %{"secret" => "se#{String.duplicate("*", 20)}"}}
      assert_received {:update, query}
      assert query.changes[:response_body] == inspect(obfuscated_response_body)
    end

    test "obfuscate nil values, binary, and integer", %{bypass: bypass} do
      params = %{
        "data" => %{"binary" => "binary", "empty_binary" => "", "nil" => nil, "integer" => 123}
      }

      Bypass.expect_once(bypass, "POST", "/test", fn conn ->
        encoded_params = Jason.encode!(params)
        {:ok, ^encoded_params, conn} = conn |> Plug.Conn.read_body()
        Plug.Conn.resp(conn, 200, %{"data" => "data"} |> Jason.encode!())
      end)

      assert {:ok, _} =
               AntlHttpClient.request(
                 InsecureFinch,
                 "api_provider",
                 %{
                   method: :post,
                   resource: "#{base_url()}/test",
                   headers: %{"authorization" => "token", "content-type" => "application/json"},
                   body: params
                 },
                 obfuscate_keys: ["binary", "empty_binary", "nil", "integer"],
                 logger: :app_recorder
               )

      obfuscated_request_body =
        Jason.encode!(%{
          "data" => %{
            "nil" => nil,
            "binary" => "bi#{String.duplicate("*", 20)}",
            "empty_binary" => "",
            "integer" => "12#{String.duplicate("*", 20)}"
          }
        })

      assert_received {:insert, query}
      assert query.fields[:request_body] == obfuscated_request_body
    end

    test "obfuscate supports list", %{bypass: bypass} do
      params = %{"data" => [%{"secret" => "secret"}]}

      Bypass.expect_once(bypass, "POST", "/test", fn conn ->
        encoded_params = Jason.encode!(params)
        {:ok, ^encoded_params, conn} = conn |> Plug.Conn.read_body()
        Plug.Conn.resp(conn, 200, %{"data" => "data"} |> Jason.encode!())
      end)

      assert {:ok, _} =
               AntlHttpClient.request(
                 InsecureFinch,
                 "api_provider",
                 %{
                   method: :post,
                   resource: "#{base_url()}/test",
                   headers: %{"authorization" => "token", "content-type" => "application/json"},
                   body: params
                 },
                 obfuscate_keys: ["secret"],
                 logger: :app_recorder
               )

      obfuscated_request_body =
        Jason.encode!(%{"data" => [%{"secret" => "se#{String.duplicate("*", 20)}"}]})

      assert_received {:insert, query}
      assert query.fields[:request_body] == obfuscated_request_body
    end

    test "when the enable_logging_via_app_recorder? is disabled, do not record the outgoing requests",
         %{bypass: bypass} do
      Bypass.expect_once(bypass, "POST", "/", fn conn ->
        Plug.Conn.resp(conn, 200, "{}")
      end)

      assert {:ok, %{}} =
               AntlHttpClient.request(
                 InsecureFinch,
                 "api_provider",
                 %{method: :post, resource: "#{base_url()}/", headers: headers(), body: %{}},
                 logger: Logger
               )

      refute_received {:insert, _}
    end

    test "ssl" do
      assert {:error, error} =
               AntlHttpClient.request(
                 SecureFinch,
                 "api_provider",
                 %{
                   method: :get,
                   resource: "https://untrusted-root.badssl.com/",
                   headers: headers(),
                   body: %{}
                 },
                 logger: :app_recorder,
                 allow_insecure?: false
               )

      assert error =~ ~r/CLIENT ALERT: Fatal - Unknown CA/
      assert_received {:update, query}
      %{client_error_message: client_error_message} = query.changes |> Enum.into(%{})
      assert client_error_message =~ ~r/CLIENT ALERT: Fatal - Unknown CA/
    end

    test "bypassed ssl" do
      assert AntlHttpClient.request(
               InsecureFinch,
               "api_provider",
               %{
                 method: :get,
                 resource: "https://untrusted-root.badssl.com/",
                 headers: headers(),
                 body: %{}
               },
               logger: :app_recorder
             )

      assert_received {:update, query}
      %{success: true} = query.changes |> Enum.into(%{})
    end
  end
end
