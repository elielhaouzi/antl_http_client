defmodule AntlHttpClient do
  @moduledoc false

  require Logger
  alias AppRecorder.OutgoingRequests

  @default_receive_timeout 50_000
  @default_logger Logger

  @doc """
  Provides an finch instance that allows insecure requests
  """

  def insecure_finch_child_spec(name) do
    conn_opts = [transport_opts: [verify: :verify_none]]

    %{
      id: name,
      start: {Finch, :start_link, [[name: name, pools: %{default: [conn_opts: conn_opts]}]]}
    }
  end

  @doc """
  Provides an finch instance that allows secure requests only
  """
  def secure_finch_child_spec(name, transport_opts) when is_list(transport_opts) do
    conn_opts = [
      transport_opts: [
        certfile: Keyword.fetch!(transport_opts, :certfile),
        keyfile: Keyword.fetch!(transport_opts, :keyfile)
      ]
    ]

    %{
      id: name,
      start: {Finch, :start_link, [[name: name, pools: %{default: [conn_opts: conn_opts]}]]}
    }
  end

  @doc """
  Helper to send a request via the finch instance
  """
  @spec request(
          module,
          binary,
          %{
            required(:method) => atom,
            required(:resource) => binary,
            required(:headers) => map,
            required(:body) => map
          },
          keyword
        ) :: {:ok, map | binary} | {:error, binary}
  def request(
        finch_instance,
        api_provider,
        %{
          method: method,
          resource: resource,
          headers: %{"content-type" => _} = headers,
          body: %{} = body
        },
        opts \\ []
      ) do
    user_agent = Keyword.get(opts, :user_agent)

    request_headers =
      if user_agent, do: %{"user-agent" => user_agent} |> Map.merge(headers), else: headers

    %{
      request_method: method,
      request_url: resource,
      request_headers: request_headers,
      request_body: body,
      requested_at: DateTime.utc_now()
    }
    |> send_request(finch_instance, api_provider,
      obfuscate_keys: Keyword.get(opts, :obfuscate_keys, []),
      logger: Keyword.get(opts, :logger, @default_logger),
      receive_timeout: Keyword.get(opts, :receive_timeout, @default_receive_timeout),
      user_agent: user_agent
    )
    |> handle_response()
  end

  defp send_request(request, finch_instance, api_provider, opts) do
    logger = Keyword.fetch!(opts, :logger)

    log_before_request_result = log_before_request(api_provider, request, logger, opts)

    request
    |> do_send_request(finch_instance, opts)
    |> tap(&log_after_request(&1, log_before_request_result, logger, opts))
  end

  defp do_send_request(request, finch_instance, opts) do
    receive_timeout = Keyword.fetch!(opts, :receive_timeout)

    Finch.build(
      request.request_method,
      request.request_url,
      Map.to_list(request.request_headers),
      encode!(request.request_headers["content-type"], request.request_body)
    )
    |> Finch.request(finch_instance, receive_timeout: receive_timeout)
    |> case do
      {:ok, %Finch.Response{body: response_body, headers: headers, status: status}} ->
        response_body =
          case Jason.decode(response_body) do
            {:ok, decoded_response_body} -> decoded_response_body
            _ -> response_body
          end

        %{
          response_body: response_body,
          response_headers: Map.new(headers),
          response_http_status: status,
          responded_at: DateTime.utc_now(),
          success: status in 200..299
        }

      {:error, error} ->
        %{client_error_message: Exception.message(error), success: false}
    end
  end

  defp handle_response(%{} = response) do
    case response do
      %{success: true, response_body: response_body} ->
        {:ok, response_body}

      %{client_error_message: "connection refused"} ->
        {:error, "connection_refused"}

      %{client_error_message: "timeout"} ->
        {:error, "timeout"}

      %{response_http_status: status, response_body: %{"error" => error}}
      when status in 400..499 and is_binary(error) ->
        {:error, error}

      %{response_http_status: 400} ->
        {:error, "bad_request"}

      %{response_http_status: 401} ->
        {:error, "unauthorized"}

      %{response_http_status: 403} ->
        {:error, "forbidden"}

      %{response_http_status: 404} ->
        {:error, "not_found"}

      %{response_http_status: status} when status >= 500 ->
        {:error, "server_error"}

      _ ->
        {:error, "unknown_error"}
    end
  end

  defp log_before_request(api_provider, request, :app_recorder, opts) do
    build_outgoing_request_create_params(api_provider, request, opts)
    |> OutgoingRequests.record_outgoing_request!()
  end

  defp log_before_request(api_provider, request, Logger, opts) do
    build_outgoing_request_create_params(api_provider, request, opts)
    |> tap(&Logger.debug("#{String.capitalize(api_provider)}Client request:, #{inspect(&1)}"))
  end

  defp log_after_request(response, outgoing_request, :app_recorder, opts) do
    build_outgoing_request_update_params(response, opts)
    |> then(&OutgoingRequests.update_outgoing_request!(outgoing_request, &1))
  end

  defp log_after_request(response, outgoing_request, Logger, opts) do
    build_outgoing_request_update_params(response, opts)
    |> tap(
      &Logger.debug(
        "#{String.capitalize(outgoing_request.destination)}Client request:, #{inspect(&1)}"
      )
    )
  end

  defp build_outgoing_request_create_params(api_provider, request, opts) do
    obfuscate_keys = Keyword.get(opts, :obfuscate_keys, [])

    obfuscate_request = obfuscate_request(request, obfuscate_keys)

    %{
      destination: "#{api_provider}",
      request_body: obfuscate_request.request_body,
      request_headers: obfuscate_request.request_headers,
      request_method: "#{request.request_method}",
      request_url: obfuscate_request.request_url,
      requested_at: obfuscate_request.requested_at,
      source: "#{api_provider}_client"
    }
  end

  defp build_outgoing_request_update_params(response, opts) do
    obfuscate_keys = Keyword.get(opts, :obfuscate_keys, [])
    obfuscated_response = obfuscate_response(response, obfuscate_keys)

    %{
      client_error_message: obfuscated_response[:client_error_message],
      response_body: inspect(obfuscated_response[:response_body]),
      response_http_status: obfuscated_response[:response_http_status],
      response_headers: obfuscated_response[:response_headers],
      responded_at: obfuscated_response[:responded_at],
      success: response.success
    }
  end

  defp obfuscate_request(request, obfuscate_keys) do
    obfuscated_request_body =
      encode!(
        request.request_headers["content-type"],
        obfuscate(request.request_body, obfuscate_keys)
      )

    obfuscted_request_headers = obfuscate(request.request_headers, obfuscate_keys)

    %{
      request
      | request_body: obfuscated_request_body,
        request_headers: obfuscted_request_headers
    }
  end

  defp obfuscate_response(%{response_body: response_body} = response, obfuscate_keys) do
    obfuscated_response_body = obfuscate(response_body, obfuscate_keys)

    %{response | response_body: obfuscated_response_body}
  end

  defp obfuscate_response(response, _obfuscate_keys), do: response

  defp encode!("application/json", body), do: Jason.encode!(body)
  defp encode!("application/x-www-form-urlencoded", body), do: URI.encode_query(body, :rfc3986)

  defp obfuscate(data, obfuscate_keys) when is_map(data) do
    Map.new(data, fn
      {key, val} when is_map(val) ->
        {key, obfuscate(val, obfuscate_keys)}

      {key, val} when is_binary(val) ->
        {key, if(key in obfuscate_keys, do: obfuscate_value(val), else: val)}
    end)
  end

  defp obfuscate(data, _obfuscate_keys), do: data

  defp obfuscate_value(secret) when is_binary(secret) do
    <<head::binary-size(2), _rest::binary>> = secret

    head <> String.duplicate("*", 20)
  end
end
