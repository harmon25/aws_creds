defmodule AwsCreds do
  defstruct default_region: "", access_key_id: "", secret_access_key: "", session_token: nil
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
    IO.inspect("checking app env")
    IO.inspect(opts, label: "opts")
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
    IO.inspect("checking system env")
    IO.inspect(opts, label: "opts")

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
    IO.inspect("parsing config file")
    IO.inspect(opts, label: "opts")
    home = System.user_home!()
    creds_file = ".aws/credentials"

    {:ok, parse_result} =
      Path.join([home, creds_file])
      |> ConfigParser.parse_file()

    profile_str = Atom.to_string(opts[:profile])

    if ConfigParser.has_section?(parse_result, profile_str) do
      {:halt, {opts[:profile], new(parse_result[profile_str])}}
    else
      :cont
    end
  end

  defp do_fetch(:instance_role, opts) do
    IO.inspect(opts, label: "opts")
    IO.inspect("fetching instance role creds")
    :cont
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
    :hackney.request(
      :put,
      "http://169.254.169.254/latest/api/token",
      [headers: [{"X-aws-ec2-metadata-token-ttl-seconds", 21600}]],
      "",
      connect_timeout: 1000
    )
  end

  defp fetch_meta(:ec2) do
  end

  defp fetch_meta(:ecs) do
  end
end
