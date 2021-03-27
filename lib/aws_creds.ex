defmodule AwsCreds do
  defstruct default_region: "",
            access_key_id: "",
            secret_access_key: "",
            session_token: nil,
            expiration: nil

  @locations [:app_env, :system_env, :config, :instance_role]

  @app :aws_creds
  @aws_access_key_id "AWS_ACCESS_KEY_ID"
  @aws_secret_access_key "AWS_SECRET_ACCESS_KEY"
  @aws_session_token "AWS_SESSION_TOKEN"
  @aws_default_region "AWS_DEFAULT_REGION"

  def fetch(profile \\ :default, opts \\ []) do
    Application.get_env(@app, :locations, @locations)
    |> Enum.reduce_while([], fn loc, acc ->
      loc_opts = Application.get_env(@app, loc, [])

      do_fetch(loc, profile: loc_opts[:profile] || profile, opts: opts ++ loc_opts)
      |> case do
        :cont ->
          {:cont, acc ++ [{loc, :none}]}

        {:halt, {profile, val}} ->
          {:halt, acc ++ [{loc, {profile, val}}]}
      end
    end)
  end

  defp do_fetch(:app_env, opts) do
    profile = Keyword.fetch!(opts, :profile)

    Application.get_env(@app, :profiles, [])
    |> case do
      [] ->
        :cont

      profiles ->
        {:halt, {profile, new(profiles[profile])}}
    end
  end

  defp do_fetch(:system_env, opts) do
    {System.get_env(@aws_access_key_id), System.get_env(@aws_secret_access_key)}
    |> case do
      {nil, _} ->
        :cont

      {_, nil} ->
        :cont

      {aws_access_key_id, aws_secret_access_key} ->
        {:halt,
         {opts[:profile],
          new(
            aws_access_key_id,
            aws_secret_access_key,
            region(),
            System.get_env(@aws_session_token)
          )}}
    end
  end

  defp do_fetch(:config, opts) do
    home = System.user_home!()
    creds_file = ".aws/credentials"
    creds_path = Path.join([home, creds_file])

    File.read(creds_path)
    |> case do
      {:error, :enoent} ->
        :cont

      {:ok, config_contents} ->
        {:ok, parse_result} = ConfigParser.parse_string(config_contents)

        profile_str = Atom.to_string(opts[:profile])

        if ConfigParser.has_section?(parse_result, profile_str) do
          {:halt, {opts[:profile], new(parse_result[profile_str])}}
        else
          :cont
        end
    end
  end

  defp do_fetch(:instance_role, opts) do
    runtime_type()
    |> fetch_instance_creds()
    |> case do
      {:ok,
       %{"AccessKeyId" => access_key_id, "SecretAccessKey" => secret_access_key, "Token" => token}} ->
        {:halt, {opts[:profile], new(access_key_id, secret_access_key, region(), token)}}

      _ ->
        :cont
    end
  end

  defp region() do
    case {System.get_env(@aws_default_region), Application.get_env(@app, :default_region)} do
      {nil, nil} -> raise RuntimeError, "missing default region"
      {nil, region} -> region
      {region, nil} -> region
      {region, _reg} -> region
    end
  end

  defp new(access_key_id, secret_access_key, region, token \\ nil) do
    %__MODULE__{
      access_key_id: access_key_id,
      secret_access_key: secret_access_key,
      default_region: region || region(),
      session_token: token
    }
  end

  defp new(
         %{"aws_access_key_id" => access_key_id, "aws_secret_access_key" => secret_access_key} =
           creds
       ) do
    new(access_key_id, secret_access_key, creds["default_region"] || region())
  end

  defp new(%{access_key_id: access_key_id, secret_access_key: secret_access_key} = creds) do
    new(access_key_id, secret_access_key, creds["default_region"] || region())
  end

  def runtime_type() do
    fetch_imdsv2_token()
    |> case do
      {:ok, token} ->
        {:ec2, token}

      _ ->
        {:ecs, nil}
    end
  end

  def fetch_iam_info(token) do
    "http://169.254.169.254/latest/meta-data/iam/info"
    |> http_get_req([{"x-aws-ec2-metadata-token", token}])
    |> case do
      {:ok, json_str} ->
        Jason.decode(json_str)

      _ ->
        {:error, :not_ec2}
    end
  end

  def parse_role_arn("arn:aws:iam::" <> rest) do
    String.split(rest, "/")
    |> List.last()
  end

  defp fetch_role(token) do
    fetch_iam_info(token)
    |> case do
      {:ok, %{"InstanceProfileArn" => arn}} -> parse_role_arn(arn)
      {:error, :not_ec2} -> {:error, :not_ec2}
    end
  end

  defp fetch_instance_creds({:ec2, token}) do
    role = fetch_role(token)

    "http://169.254.169.254/latest/meta-data/iam/security-credentials/#{role}"
    |> http_get_req([{"x-aws-ec2-metadata-token", token}])
    |> case do
      {:ok, json_str} ->
        Jason.decode(json_str)

      _ ->
        {:error, :not_ec2}
    end
  end

  defp fetch_instance_creds({:ecs, _}) do
    relative_uri = System.get_env("AWS_CONTAINER_CREDENTIALS_RELATIVE_URI")

    http_get_req("http://169.254.170.2" <> relative_uri)
    |> case do
      {:ok, json_str} ->
        Jason.decode(json_str)

      _ ->
        {:error, :not_ec2}
    end
  end

  def http_get_req(url, headers \\ []) do
    :hackney.request(
      :get,
      url,
      headers
    )
    |> case do
      {:ok, 200, _headers, ref} ->
        :hackney.body(ref)

      _ ->
        {:error, :not_ec2}
    end
  end

  def fetch_imdsv2_token() do
    :hackney.request(
      :put,
      "http://169.254.169.254/latest/api/token",
      [{"x-aws-ec2-metadata-token-ttl-seconds", "21600"}],
      "",
      connect_timeout: 1000
    )
    |> case do
      {:ok, 200, _headers, ref} -> :hackney.body(ref)
      _ -> {:error, :none}
    end
  end
end
