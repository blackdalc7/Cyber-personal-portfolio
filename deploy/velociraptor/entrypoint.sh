#!/bin/sh
# First start: generate a server config (fresh CA and keys, kept in the velo-data volume), a client
# config for the lab endpoints, and an API client config that 09-evidence-timeline uses over gRPC.
set -eu
cd /velo
if [ ! -f server.config.yaml ]; then
  velociraptor config generate --merge "{
    \"Client\": {\"server_urls\": [\"${VELO_PUBLIC_URL}\"]},
    \"API\": {\"bind_address\": \"0.0.0.0\", \"bind_port\": 8001},
    \"GUI\": {\"bind_address\": \"0.0.0.0\", \"bind_port\": 8889},
    \"Frontend\": {\"bind_address\": \"0.0.0.0\", \"bind_port\": 8000, \"hostname\": \"velociraptor\"},
    \"Datastore\": {\"location\": \"/velo/datastore\", \"filestore_directory\": \"/velo/filestore\"},
    \"Logging\": {\"output_directory\": \"/velo/logs\", \"separate_logs_per_component\": true}
  }" > server.config.yaml
  velociraptor --config server.config.yaml config client > client.config.yaml
  velociraptor --config server.config.yaml config api_client --name watchfloor-evidence \
    --role api,investigator api.config.yaml
  # The API client dials the server by its compose service name.
  sed -i 's#^api_connection_string: .*#api_connection_string: velociraptor:8001#' api.config.yaml
  # Group-readable so the evidence service (group 10002 in compose) can read the API config, nobody else.
  chmod 0640 server.config.yaml api.config.yaml
  echo "Velociraptor configs written to the velo-data volume."
  echo "Create a GUI user with: docker compose exec velociraptor velociraptor --config /velo/server.config.yaml user add <name> --role administrator"
fi
exec velociraptor --config server.config.yaml frontend -v
