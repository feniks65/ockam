if Code.ensure_loaded?(:telemetry) do
  defmodule Ockam.TelemetryLogger do
    require Logger

    def handle_event(event, measurements, metadata, _config) do
      Logger.info(
        "\n\n===> \n#{inspect(event)}, \n#{inspect(measurements)}, \n#{inspect(metadata)}"
      )
    end

    def attach() do
      events = [
        [:ockam, Ockam.Router, :route, :stop]
      ]
      Application.loaded_applications() # from all loaded applications
        |> Enum.flat_map(fn({app, _, _}) -> Application.spec(app, :modules) end) # list all modules
        |> Enum.filter(fn(module) -> String.starts_with?(to_string(module), "Elixir.Ockam") end) # only take those starting with Ockam.
        |> Enum.filter(fn(module) ->
          Enum.member?(
            module.module_info(:attributes) # from module attributes
              |> Keyword.get_values(:behaviour) # get all behaviours
              |> List.flatten,
            Ockam.Worker) # contains Ockam.Worker
        end)
      :telemetry.attach_many("logger", events, &TelemetryLogger.handle_event/4, nil)
  end
end
