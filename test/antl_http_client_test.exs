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

    test "adds user_agent if given", %{bypass: bypass} do
      params = %{"data" => "data"}
      user_agent = "App/1.0; +(https://example.net/app)"

      Bypass.expect_once(bypass, "POST", "/test", fn conn ->
        assert Plug.Conn.get_req_header(conn, "user-agent") == [user_agent]
        Plug.Conn.resp(conn, 200, Jason.encode!(%{"data" => "data"}))
      end)

      assert {:ok, _} =
               AntlHttpClient.request(InsecureFinch, "api_provider", %{
                 method: :post,
                 resource: "#{base_url()}/test",
                 headers: %{"content-type" => "application/json", "user-agent" => user_agent},
                 body: params
               })
    end

    test "bad_request error", %{bypass: bypass} do
      Bypass.expect_once(bypass, "POST", "/test", fn conn ->
        Plug.Conn.resp(conn, 400, "bad_request")
      end)

      assert {:error, "bad_request"} ==
               AntlHttpClient.request(
                 InsecureFinch,
                 "api_provider",
                 %{method: :post, resource: "#{base_url()}/test", headers: headers(), body: %{}},
                 []
               )
    end

    test "returns the error message if there is one", %{bypass: bypass} do
      Bypass.expect_once(bypass, "POST", "/test", fn conn ->
        Plug.Conn.resp(conn, 403, Jason.encode!(%{"error" => "the error"}))
      end)

      assert {:error, "the error"} ==
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

      assert {:error, "connection_refused"} =
               AntlHttpClient.request(InsecureFinch, "api_provider", %{
                 method: :post,
                 resource: "#{base_url()}/test",
                 headers: headers(),
                 body: %{}
               })
    end

    test "when app_recorder is enabled, records outgoing requests with `authorization` and obfuscated_keys obfuscated",
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
                 obfuscate_keys: ["secret", "authorization"],
                 logger: :app_recorder
               )

      obfuscated_request_body =
        Jason.encode!(%{
          "secret" => "se#{String.duplicate("*", 20)}",
          "data" => "data"
        })

      assert_received {:insert, query}
      assert query.fields[:request_body] == obfuscated_request_body
      assert %{"authorization" => authorization} = query.fields[:request_headers]
      assert authorization == "to#{String.duplicate("*", 20)}"

      obfuscated_response_body = %{
        "secret" => "se#{String.duplicate("*", 20)}",
        "data" => "data"
      }

      assert_received {:update, query}
      assert query.changes[:response_body] == inspect(obfuscated_response_body)
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
      assert {:error, "unknown_error"} =
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
