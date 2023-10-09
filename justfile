set dotenv-load

default:
  @just --choose

# Connect with the database
db:
  usql $(echo $DATABASE_URL | sed 's/.\{7\}$//')

# Start the docker containers
start:
  docker compose up

# Run the backend server, to migrate run `just run migrate`
run argv="@":
  #!/usr/bin/env bash
  set -euxo pipefail
  if [[ {{ argv }} == "migrations" ]]
  then
    go run cmd/main.go -migrations
  else
    go run cmd/main.go
  fi

