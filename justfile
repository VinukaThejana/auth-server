set dotenv-load

default:
  @just --choose

# Connect with the database
db:
  usql $(echo $DATABASE_URL)

# Start the docker containers
start:
  docker compose up

# Run the backend server, to migrate run `just run migrate`
run argv="@":
  #!/usr/bin/env bash
  set -euxo pipefail
  if [[ {{ argv }} == "migrate" ]]
  then
    go run cmd/main.go -migrate
  else
    go run cmd/main.go
  fi

redis argv="session":
  #!/usr/bin/env bash
  set -euxo pipefail
  if [[ {{ argv }} == "session" ]]
  then
    nc localhost 6379 -v
  elif [[ {{ argv }} == "email" ]]
  then
    nc localhost 6381 -v
  elif [[ {{ argv }} == "system" ]]
  then
    nc localhost 6382 -v
  elif [[ {{ argv }} == "ratelimiter" ]]
  then
    nc localhost 6380 -v
  elif [[ {{ argv }} == "challenge" ]]
  then
    nc localhost 6383 -v
  else
    echo "Not a valid Redis database"
  fi


test argv1 argv2 argument1="" argument2="" argument3="" argument4="":
  #!/usr/bin/env bash
  set -euxo pipefail
  path="tests/{{ argv1 }}/{{ argv2 }}.lua"

  lua "$path" {{ argument1 }} {{ argument2 }} {{ argument3 }} {{ argument4 }}

env:
  doppler secrets download --no-file --format env > .env
  cp .env ./api/Auth\ server
