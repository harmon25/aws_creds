defmodule AwsCreds.Cache do
  use GenServer

  @table_name __MODULE__.ETS

  def start_link(init_args) do
    GenServer.start_link(__MODULE__, [init_args], name: __MODULE__)
  end

  def init(_args) do
    ets_table = :ets.new(@table_name, [:set, :named_table, :protected, read_concurrency: true])
    {:ok, %{ets_table: ets_table, refreshed_at: nil}}
  end

  def insert(profile, config_values) when is_map(config_values) do
    GenServer.call(__MODULE__, {:insert, profile, config_values})
  end

  def insert(_profile, _config_values) do
    {:error, "#{__MODULE__} expected `config_values` to be a map"}
  end

  def fetch(profile) do
    case :ets.lookup(@table_name, profile) do
      [{^profile, config_vals}] -> {:ok, config_vals}
      [] -> :error
    end
  end

  def fetch_default(), do: fetch(:default)
  def fetch_profile(profile), do: fetch(profile)

  def handle_call({:insert, key, value}, _from, state) do
    :ets.insert(state.ets_table, {key, value})
    {:reply, :ok, state}
  end
end
