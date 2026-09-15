#! /usr/bin/env bash
set -o pipefail

APP_DIR=$(realpath "$(dirname "$0")/../..")
DB_DIR=$APP_DIR/backend/db
DB_NAME=test-database.sqlite3
DB_INIT_NAME=test-database-initial.sqlite3
DB_INIT_HASH_NAME=$DB_INIT_NAME.sha256

SCRIPT_LONG_ARGS=()
SCRIPT_SHORT_ARGS=()
TEST_PATHS=()

BACKEND_PORT=8173
FRONTEND_PORT=4173
MAILER_WEB_SERVER_PORT=8073
MAILER_SMTP_SERVER_PORT=1073

ENTERPRISE_SETTINGS="enterprise_core.settings"

KEYCLOAK_PORT=8080
KEYCLOAK_ADMIN="admin"
KEYCLOAK_ADMIN_PASSWORD="admin"

QUICK_MODE_ACTIVATED=1
KEEP_DATABASE_SNAPSHOT=1

# Resource handles are owned by this invocation only. Do not inherit values
# with these names from the caller: cleanup must never target another process
# or container.
BACKEND_PID=""
MAILER_PID=""
KEYCLOAK_PID=""

# Check if user can run docker without sudo
if docker info >/dev/null 2>&1; then
  DO_NOT_USE_SUDO=1
fi

for arg in "$@"; do
  if [[ $arg == --port* ]]; then
    if [[ "${arg#*=}" =~ ^[0-9]+$ ]]; then
      BACKEND_PORT="${arg#*=}"
    else
      echo "Invalid format for --port argument. Please use --port=PORT"
      exit 1
    fi
  elif [[ $arg == --mailer* ]]; then
    MAILER_PORTS="${arg#*=}"
    if [[ $MAILER_PORTS =~ ^[0-9]+/[0-9]+$ ]]; then
      IFS='/' read -ra PORTS <<<"$MAILER_PORTS"
      MAILER_SMTP_SERVER_PORT="${PORTS[0]}"
      MAILER_WEB_SERVER_PORT="${PORTS[1]}"
      USE_EXISTING_MAILER=1
    else
      echo "Invalid format for --mailer argument. Please use --mailer=PORT/PORT"
      exit 1
    fi
  elif [[ $arg == -m ]]; then
    USE_EXISTING_MAILER=1
  elif [[ $arg == -e ]] || [[ $arg == --enterprise ]]; then
    ENTERPRISE=1
  elif [[ $arg == -q ]]; then
    QUICK_MODE_ACTIVATED=1
  elif [[ $arg == --no-quick ]]; then
    QUICK_MODE_ACTIVATED=0
  elif [[ $arg == -v ]]; then
    STORE_BACKEND_OUTPUT=1
  elif [[ $arg == -k ]]; then
    KEEP_DATABASE_SNAPSHOT=1
  elif [[ $arg == --no-snapshot ]]; then
    KEEP_DATABASE_SNAPSHOT=0
  elif [[ $arg == --no-sudo ]]; then
    DO_NOT_USE_SUDO=1
  elif [[ $arg == --* ]]; then
    SCRIPT_LONG_ARGS+=("$arg")
  elif [[ $arg == -* ]]; then
    SCRIPT_SHORT_ARGS+=("$arg")
  elif [[ $arg != -* ]]; then
    TEST_PATHS+=("$arg")
  fi
done

DJANGO_ARGS=()
UV_RUN=(uv run)
if [[ -n "$ENTERPRISE" ]]; then
  DJANGO_ARGS=(--settings="$ENTERPRISE_SETTINGS")
  UV_RUN+=(--project "$APP_DIR/enterprise/backend")
fi
if [[ -n "${CI:-}" ]]; then
  KEEP_DATABASE_SNAPSHOT=0
fi

if [[ " ${SCRIPT_SHORT_ARGS[@]} " =~ " -h " ]] || [[ " ${SCRIPT_LONG_ARGS[@]} " =~ " --help " ]]; then
  echo "Usage: e2e-tests.sh [options] [test_path]"
  echo "Run the end-to-end tests for the CISO Assistant application."
  echo "Options:"
  echo "  -q                      Quick mode: execute only the tests 1 time with no retries and only 1 project"
  echo "  --no-quick              Disable quick mode: execute the tests with retries and all projects"
  echo "  -k                      Keep a saved snapshot of the initial database and use it to avoid executing useless migrations."
  echo "                          If the initial database hasn't been created running the tests with this option will create it."
  echo "                          Running the tests without this option will delete the saved initial database."
  echo "  --no-snapshot           Do not keep a saved snapshot of the initial database, the database will be created from scratch."
  echo "  --no-sudo               Run docker commands without using sudo as a prefix."
  echo "  --port=PORT             Run the backend server on the specified port (default: $BACKEND_PORT)"
  echo "  -m, --mailer=PORT/PORT  Use an existing mailer service on the optionally defined ports (default: $MAILER_SMTP_SERVER_PORT/$MAILER_WEB_SERVER_PORT)"
  echo "  -e, --enterprise        Run the tests on the enterprise version of the CISO Assistant"

  echo "Playwright options:"
  echo "  --browser=NAME          Run the tests in the specified browser (chromium, firefox, webkit)"
  echo "  --global-timeout=MS     Maximum time this test suite can run in milliseconds (default: unlimited)"
  echo "  --grep=SEARCH           Only run tests matching this regular expression (default: \".*\")"
  echo "  --headed                Run the tests in headful mode"
  echo "  -h                      Show this help message and exit"
  echo "  --list                  List all the tests"
  echo "  --project=NAME          Run the tests in the specified project (chromium, firefox, webkit)"
  echo "  --repeat-each=COUNT     Run the tests the specified number of times (default: 1)"
  echo "  --retries=COUNT         Set the number of retries for the tests"
  echo "  --timeout=MS            Set the timeout for the tests in milliseconds"
  echo "  -v                      Show the output of the backend server"
  echo -e "  --workers=COUNT         Number of concurrent workers or percentage of logical CPU cores, use 1 to run in a single worker (default: 1)"
  echo "                          Be aware that increasing the number of workers may reduce tests accuracy and stability"
  exit 0
fi

if [[ "$(id -u "$(whoami)")" -eq 0 ]]; then
  echo "Running this script with a root account is highly discouraged as it can cause bugs with playwright."
fi

if nc -z -w1 localhost $BACKEND_PORT 2>/dev/null; then
  echo "The port $BACKEND_PORT is already in use!"
  echo "You can either:"
  echo "- Kill the process which is currently using this port."
  echo "- Change the backend test server port using --port=NEW_PORT and try again."
	exit 1
fi

# Playwright may reuse an existing preview server outside CI. That can serve a
# stale build or disappear with a previous test process, producing false
# product failures. Every harness invocation owns its frontend process.
if nc -z -w1 localhost $FRONTEND_PORT 2>/dev/null; then
	echo "The frontend port $FRONTEND_PORT is already in use!"
	echo "Please stop the existing preview server before running this harness."
	exit 1
fi

for PORT in $MAILER_WEB_SERVER_PORT $MAILER_SMTP_SERVER_PORT; do
  if nc -z -w1 localhost $PORT 2>/dev/null; then
    if [[ -z "$USE_EXISTING_MAILER" ]]; then
      echo "The port $PORT is already in use!"
      echo "Please stop the running process using the port or change the mailer port and try again."
      exit 1
    fi
  elif [[ -n "$USE_EXISTING_MAILER" ]]; then
    echo "No mailer service is running on port $PORT!"
    echo "Please start a mailer service on port $PORT or change the mailer port using --mailer=PORT/PORT and try again."
    echo "You can also use the isolated test mailer service by removing the -m option."
    exit 1
  fi
done

stop_backend_server() {
  local attempt
  local pid="$1"
  local port="$2"

  if kill -0 "$pid" 2>/dev/null; then
    kill "$pid" >/dev/null 2>&1 || true
  fi

  for ((attempt = 1; attempt <= 20; attempt++)); do
    if ! kill -0 "$pid" 2>/dev/null && ! nc -z -w1 localhost "$port" 2>/dev/null; then
      wait "$pid" >/dev/null 2>&1 || true
      return 0
    fi
    sleep 0.25
  done

  # The uv wrapper should forward TERM. If it did not exit, make one bounded
  # final attempt against the exact PID created by this invocation.
  if kill -0 "$pid" 2>/dev/null; then
    kill -KILL "$pid" >/dev/null 2>&1 || true
  fi
  for ((attempt = 1; attempt <= 20; attempt++)); do
    if ! kill -0 "$pid" 2>/dev/null && ! nc -z -w1 localhost "$port" 2>/dev/null; then
      wait "$pid" >/dev/null 2>&1 || true
      return 0
    fi
    sleep 0.25
  done

  return 1
}

remove_owned_container() {
  local label="$1"
  local container_id="$2"
  local attempt
  local matching_ids
  local docker_command=(docker)

  if [[ -z "$DO_NOT_USE_SUDO" ]]; then
    docker_command=(sudo docker)
  fi

  # Give the service a short graceful stop, then force removal only for the
  # exact container ID returned by this invocation's `docker run`.
  "${docker_command[@]}" stop --time 5 "$container_id" >/dev/null 2>&1 || true
  "${docker_command[@]}" rm -f "$container_id" >/dev/null 2>&1 || true

  for ((attempt = 1; attempt <= 20; attempt++)); do
    if matching_ids=$("${docker_command[@]}" ps -aq --no-trunc --filter "id=$container_id" 2>/dev/null); then
      if [[ -z "$matching_ids" ]]; then
        echo "| $label service stopped"
        return 0
      fi
    fi
    sleep 0.25
  done

  echo "| ERROR: $label container $container_id is still present or Docker could not verify its removal" >&2
  return 1
}

cleanup() {
  local exit_code="${1:-0}"
  local cleanup_failed=0

  # Prevent a second signal from recursively entering cleanup while Docker or
  # the backend is being stopped.
  trap - SIGINT SIGTERM EXIT
  echo -e "\nCleaning up..."
  if [[ -n "$BACKEND_PID" ]]; then
    if stop_backend_server "$BACKEND_PID" "$BACKEND_PORT"; then
      echo "| backend server stopped"
    else
      echo "| ERROR: backend PID $BACKEND_PID or port $BACKEND_PORT is still active" >&2
      cleanup_failed=1
    fi
  fi
  if ! rm -f -- "$DB_DIR/$DB_NAME"; then
    echo "| ERROR: working test database could not be removed" >&2
    cleanup_failed=1
  fi
  if [[ "$KEEP_DATABASE_SNAPSHOT" -ne 1 || ! -f "$DB_DIR/$DB_INIT_NAME" || ! -f "$DB_DIR/$DB_INIT_HASH_NAME" ]]; then
    if rm -f -- "$DB_DIR/$DB_INIT_NAME" "$DB_DIR/$DB_INIT_HASH_NAME"; then
      echo "| test initial database snapshot deleted"
    else
      echo "| ERROR: test initial database snapshot could not be removed" >&2
      cleanup_failed=1
    fi
  fi
  if [[ -n "$MAILER_PID" ]]; then
    remove_owned_container "mailer" "$MAILER_PID" || cleanup_failed=1
  fi
  if [[ -n "$KEYCLOAK_PID" ]]; then
    remove_owned_container "keycloak" "$KEYCLOAK_PID" || cleanup_failed=1
  fi
  if [[ -d "$APP_DIR/frontend/tests/utils/.testhistory" ]]; then
    if rm -rf -- "$APP_DIR/frontend/tests/utils/.testhistory"; then
      echo "| test data history removed"
    else
      echo "| ERROR: test data history could not be removed" >&2
      cleanup_failed=1
    fi
  fi

  if [[ "$cleanup_failed" -ne 0 ]]; then
    if [[ "$exit_code" -eq 0 ]]; then
      exit_code=1
      echo "Cleanup failed after otherwise successful tests." >&2
    else
      echo "Cleanup was incomplete; preserving the original test exit code $exit_code." >&2
    fi
  else
    echo "Cleanup done"
    if [[ "$exit_code" -eq 0 ]]; then
      echo "Test successfully completed!"
    fi
  fi
  exit "$exit_code"
}

build_frontend() {
  if [[ -n "$ENTERPRISE" ]]; then
    echo "Building the enterprise version of the frontend..."
    cd "$APP_DIR"/enterprise/frontend || return 1
    make clean && make
  else
    echo "Building the community version of the frontend..."
    pnpm run build
  fi
}

compute_frontend_hash() {
  local edition="community"
  local inputs=(
    "$APP_DIR/frontend/ciso-theme.css"
    "$APP_DIR/frontend/package.json"
    "$APP_DIR/frontend/pnpm-lock.yaml"
    "$APP_DIR/frontend/pnpm-workspace.yaml"
    "$APP_DIR/frontend/svelte.config.js"
    "$APP_DIR/frontend/tsconfig.json"
    "$APP_DIR/frontend/vite.config.ts"
  )
  local source_path

  while IFS= read -r -d '' source_path; do
    inputs+=("$source_path")
  done < <(
    find "$APP_DIR/frontend/src" \
      -path "$APP_DIR/frontend/src/paraglide" -prune -o \
      -type f -print0
    find "$APP_DIR/frontend/messages" "$APP_DIR/frontend/project.inlang" "$APP_DIR/frontend/static" \
      -type f -print0
  )

  if [[ -n "$ENTERPRISE" ]]; then
    edition="enterprise"
    echo "Computing the hash for the enterprise version of the frontend..." >&2
    for source_path in \
      "$APP_DIR/enterprise/frontend/Dockerfile" \
      "$APP_DIR/enterprise/frontend/Makefile"; do
      [[ -f "$source_path" ]] && inputs+=("$source_path")
    done
    while IFS= read -r -d '' source_path; do
      inputs+=("$source_path")
    done < <(find "$APP_DIR/enterprise/frontend/src" -type f -print0)
  fi

  {
    # The preview build is only reusable for the exact harness environment that
    # produced it. In particular, changing --port must not keep a build whose
    # backend URL points at the previous test server.
    printf 'build-context:%s\0' \
      "edition=$edition" \
      "origin=${ORIGIN:-}" \
      "public_backend_api_url=${PUBLIC_BACKEND_API_URL:-}" \
      "backend_port=$BACKEND_PORT" \
      "frontend_port=$FRONTEND_PORT" \
      "mailer_smtp_port=$MAILER_SMTP_SERVER_PORT" \
      "mailer_web_port=$MAILER_WEB_SERVER_PORT" \
      "keycloak_port=$KEYCLOAK_PORT"
    printf '%s\0' "${inputs[@]}" | sort -z | xargs -0 sha256sum
  } | sha256sum
}

compute_database_snapshot_hash() {
  local inputs=(
    "$APP_DIR/backend/ciso_assistant/settings.py"
    "$APP_DIR/backend/core/startup.py"
    "$APP_DIR/backend/manage.py"
    "$APP_DIR/backend/pyproject.toml"
    "$APP_DIR/backend/uv.lock"
  )
  local source_path

  while IFS= read -r -d '' source_path; do
    inputs+=("$source_path")
  done < <(
    find "$APP_DIR/backend" \
      -type d \( \
        -name .venv -o \
        -name venv -o \
        -name node_modules -o \
        -name vendor -o \
        -name .tox -o \
        -name .nox \
      \) -prune -o \
      -path '*/migrations/*.py' -type f -print0
    find "$APP_DIR/backend/library" -type f \( -name '*.py' -o -name '*.yaml' \) -print0
  )
  if [[ -n "$ENTERPRISE" && -d "$APP_DIR/enterprise/backend" ]]; then
    inputs+=(
      "$APP_DIR/enterprise/backend/pyproject.toml"
      "$APP_DIR/enterprise/backend/uv.lock"
    )
    while IFS= read -r -d '' source_path; do
      inputs+=("$source_path")
    done < <(find "$APP_DIR/enterprise/backend/enterprise_core" -type f -name '*.py' -print0)
  fi

  printf '%s\0' "${inputs[@]}" | sort -z | xargs -0 sha256sum | sha256sum
}

run_tests() {
  local playwright_paths=()
  local quick_args=()

  if [[ -n "$ENTERPRISE" ]]; then
    echo "Running tests for the enterprise version..."
    cd "$APP_DIR"/enterprise/frontend || return 1
    make pre-tests || return $?
    cd "$APP_DIR"/enterprise/frontend/.build/frontend || return 1
  else
    echo "Running tests for the community version..."
  fi

  if ((${#TEST_PATHS[@]} == 0)); then
    playwright_paths=("./tests/functional")
  else
    for test_path in "${TEST_PATHS[@]}"; do
      playwright_paths+=("./tests/functional/$test_path")
    done
  fi

  if ((QUICK_MODE_ACTIVATED == 1)); then
    quick_args=(--project=chromium --retries=0)
  fi

  pnpm playwright test "${playwright_paths[@]}" "${quick_args[@]}" "${SCRIPT_LONG_ARGS[@]}" "${SCRIPT_SHORT_ARGS[@]}"
}

wait_for_port() {
  local service_name="$1"
  local host="$2"
  local port="$3"
  local timeout_seconds="$4"
  local process_pid="${5:-}"
  local deadline=$((SECONDS + timeout_seconds))

  while ((SECONDS < deadline)); do
    if nc -z -w1 "$host" "$port" 2>/dev/null; then
      return 0
    fi
    if [[ -n "$process_pid" ]] && ! kill -0 "$process_pid" 2>/dev/null; then
      echo "$service_name exited before becoming ready on $host:$port."
      return 1
    fi
    sleep 1
  done

  echo "$service_name did not become ready on $host:$port after $timeout_seconds seconds."
  return 1
}

wait_for_http() {
  local service_name="$1"
  local url="$2"
  local timeout_seconds="$3"
  local process_pid="${4:-}"
  local deadline=$((SECONDS + timeout_seconds))

  while ((SECONDS < deadline)); do
    if curl --noproxy localhost,127.0.0.1 -fsS --connect-timeout 1 --max-time 2 "$url" >/dev/null 2>&1; then
      return 0
    fi
    if [[ -n "$process_pid" ]] && ! kill -0 "$process_pid" 2>/dev/null; then
      echo "$service_name exited before becoming ready at $url."
      return 1
    fi
    sleep 1
  done

  echo "$service_name did not become ready at $url after $timeout_seconds seconds."
  return 1
}

finish() {
  local exit_code=$?
  if [[ "$exit_code" -ne 0 ]]; then
    echo "Test failed with exit code $exit_code."
  fi
  cleanup "$exit_code"
}

trap 'cleanup 130' SIGINT
trap 'cleanup 143' SIGTERM
trap finish EXIT

if [[ -z "$USE_EXISTING_MAILER" ]]; then
  if command -v docker &>/dev/null; then
    echo "Starting mailer service..."
    if [[ -z "$DO_NOT_USE_SUDO" ]]; then
      MAILER_PID=$(sudo docker run -d -p "$MAILER_SMTP_SERVER_PORT":1025 -p "$MAILER_WEB_SERVER_PORT":8025 mailhog/mailhog) || exit $?
    else
      MAILER_PID=$(docker run -d -p "$MAILER_SMTP_SERVER_PORT":1025 -p "$MAILER_WEB_SERVER_PORT":8025 mailhog/mailhog) || exit $?
    fi
    [[ -n "$MAILER_PID" ]] || exit 1
    wait_for_port "Mailer SMTP service" localhost "$MAILER_SMTP_SERVER_PORT" 60 || exit $?
    wait_for_port "Mailer web service" localhost "$MAILER_WEB_SERVER_PORT" 60 || exit $?
    echo "Mailer service started on ports $MAILER_SMTP_SERVER_PORT/$MAILER_WEB_SERVER_PORT (Container ID: ${MAILER_PID:0:6})"
  else
    echo "Docker is not installed!"
    echo "Please install Docker to use the isolated test mailer service or use -m to tell the tests to use an existing one."
    exit 1
  fi
else
  echo "Using an existing mailer service on ports $MAILER_SMTP_SERVER_PORT/$MAILER_WEB_SERVER_PORT"
fi

if command -v docker &>/dev/null; then
  echo "Starting keycloak with admin user $KEYCLOAK_ADMIN:$KEYCLOAK_ADMIN_PASSWORD on port $KEYCLOAK_PORT..."
  if [[ -z "$DO_NOT_USE_SUDO" ]]; then
    KEYCLOAK_PID=$(sudo docker run -d -p "$KEYCLOAK_PORT":8080 \
      -e KEYCLOAK_ADMIN="$KEYCLOAK_ADMIN" \
      -e KEYCLOAK_ADMIN_PASSWORD="$KEYCLOAK_ADMIN_PASSWORD" \
      -v "$APP_DIR"/frontend/tests/keycloak:/opt/keycloak/data/import \
      quay.io/keycloak/keycloak:26.3.0 \
      start-dev --import-realm) || exit $?
  else
    KEYCLOAK_PID=$(docker run -d -p "$KEYCLOAK_PORT":8080 \
      -e KEYCLOAK_ADMIN="$KEYCLOAK_ADMIN" \
      -e KEYCLOAK_ADMIN_PASSWORD="$KEYCLOAK_ADMIN_PASSWORD" \
      -v "$APP_DIR"/frontend/tests/keycloak:/opt/keycloak/data/import \
      quay.io/keycloak/keycloak:26.3.0 \
      start-dev --import-realm) || exit $?
  fi
  [[ -n "$KEYCLOAK_PID" ]] || exit 1
  wait_for_http "Keycloak service" "http://localhost:$KEYCLOAK_PORT/realms/test/.well-known/openid-configuration" 60 || exit $?
  echo "Keycloak started on ports $KEYCLOAK_PORT (Container ID: ${KEYCLOAK_PID:0:6})"
else
  echo "Docker is not installed!"
  echo "Please install Docker to use the isolated test mailer service or use -m to tell the tests to use an existing one."
  exit 1
fi

echo "Starting backend server..."
unset POSTGRES_NAME POSTGRES_USER POSTGRES_PASSWORD
export CISO_ASSISTANT_URL=http://localhost:4173
export CISO_ASSISTANT_VERSION=$(git describe --tags --always)
export CISO_ASSISTANT_BUILD=$(git rev-parse --short HEAD)
export ALLOWED_HOSTS=localhost,127.0.0.1,0.0.0.0
export DJANGO_DEBUG=True
export DJANGO_SUPERUSER_EMAIL=admin@tests.com
export DJANGO_SUPERUSER_PASSWORD=1234
export SQLITE_FILE=db/$DB_NAME
# Small pages so pagination-regression.test.ts can reach a second page.
export PAGINATE_BY=100
export EMAIL_HOST_USER=tests@tests.com
export DEFAULT_FROM_EMAIL='ciso-assistant@tests.net'
export EMAIL_HOST=localhost
export EMAIL_HOST_PASSWORD=pwd
export EMAIL_PORT=$MAILER_SMTP_SERVER_PORT
export CISO_ASSISTANT_VERSION=$(git describe --tags --always)
export CISO_ASSISTANT_BUILD=$(git rev-parse --short HEAD)

export LICENSE_SEATS=999
# Still write the HTML report, but never start its blocking local report server;
# this preserves Playwright's failure code and lets the EXIT trap clean up.
export PLAYWRIGHT_HTML_OPEN=never

cd "$APP_DIR"/backend/ || exit 1
DATABASE_SNAPSHOT_HASH=$(compute_database_snapshot_hash) || exit $?
[[ -n "$DATABASE_SNAPSHOT_HASH" ]] || exit 1
SNAPSHOT_IS_CURRENT=0
if [[ -f "$DB_DIR/$DB_INIT_NAME" && -f "$DB_DIR/$DB_INIT_HASH_NAME" ]]; then
  EXISTING_DATABASE_SNAPSHOT_HASH=$(cat "$DB_DIR/$DB_INIT_HASH_NAME") || exit $?
  if [[ "$EXISTING_DATABASE_SNAPSHOT_HASH" == "$DATABASE_SNAPSHOT_HASH" ]]; then
    SNAPSHOT_IS_CURRENT=1
  fi
fi

"${UV_RUN[@]}" python3 manage.py makemigrations --check --dry-run "${DJANGO_ARGS[@]}" || exit $?
if [[ $KEEP_DATABASE_SNAPSHOT -ne 1 ]]; then
  rm -f -- "$DB_DIR/$DB_NAME"
  "${UV_RUN[@]}" python3 manage.py migrate "${DJANGO_ARGS[@]}" || exit $?
elif [[ $SNAPSHOT_IS_CURRENT -ne 1 ]]; then
  rm -f -- "$DB_DIR/$DB_NAME" "$DB_DIR/$DB_INIT_NAME" "$DB_DIR/$DB_INIT_HASH_NAME"
  "${UV_RUN[@]}" python3 manage.py migrate "${DJANGO_ARGS[@]}" || exit $?
  cp "$DB_DIR/$DB_NAME" "$DB_DIR/$DB_INIT_NAME" || exit $?
  printf '%s\n' "$DATABASE_SNAPSHOT_HASH" >"$DB_DIR/$DB_INIT_HASH_NAME" || exit $?
else
  # Copying the initial database instead of applying the migrations saves a lot of time
  cp "$DB_DIR/$DB_INIT_NAME" "$DB_DIR/$DB_NAME" || exit $?
fi

"${UV_RUN[@]}" python3 manage.py createsuperuser --noinput "${DJANGO_ARGS[@]}" || exit $?
if [[ -n "$STORE_BACKEND_OUTPUT" ]]; then
  nohup "${UV_RUN[@]}" python3 manage.py runserver "$BACKEND_PORT" --noreload "${DJANGO_ARGS[@]}" >"$APP_DIR"/frontend/tests/utils/.testbackendoutput.out 2>&1 &
  echo "You can view the backend server output at $APP_DIR/frontend/tests/utils/.testbackendoutput.out"
else
  nohup "${UV_RUN[@]}" python3 manage.py runserver "$BACKEND_PORT" --noreload "${DJANGO_ARGS[@]}" >/dev/null 2>&1 &
fi
BACKEND_PID=$!
wait_for_http "Test backend server" "http://localhost:$BACKEND_PORT/api/health/" 60 "$BACKEND_PID" || exit $?
echo "Test backend server started on port $BACKEND_PORT (PID: $BACKEND_PID)"

echo "Starting playwright tests"
export ORIGIN=http://localhost:4173
export PUBLIC_BACKEND_API_URL=http://localhost:$BACKEND_PORT/api
export MAILER_WEB_SERVER_PORT=$MAILER_WEB_SERVER_PORT

cd "$APP_DIR"/frontend/ || exit

if ((${#TEST_PATHS[@]} == 0)); then
  echo "| running every functional test"
else
  echo "| running tests: ${TEST_PATHS[@]}"
fi
if ((${#SCRIPT_LONG_ARGS[@]} == 0)); then
  echo "| without args"
else
  echo "| with args: ${SCRIPT_LONG_ARGS[@]}"
fi
echo "=========================================================================================="

if [[ -n "$ENTERPRISE" ]]; then
  FRONTEND_HASH_FILE="$APP_DIR/frontend/tests/.frontend_hash.enterprise"
else
  FRONTEND_HASH_FILE="$APP_DIR/frontend/tests/.frontend_hash"
fi
FRONTEND_HASH=$(compute_frontend_hash) || exit $?
[[ -n "$FRONTEND_HASH" ]] || exit 1

EXISTING_FRONTEND_HASH=""
if [[ -f "$FRONTEND_HASH_FILE" ]]; then
  EXISTING_FRONTEND_HASH=$(cat "$FRONTEND_HASH_FILE") || exit $?
fi

FRONTEND_ARTIFACT_READY=0
if [[ -n "$ENTERPRISE" ]]; then
  if [[ -d "$APP_DIR/enterprise/frontend/.build/frontend/build" && -d "$APP_DIR/enterprise/frontend/.build/frontend/node_modules" ]]; then
    FRONTEND_ARTIFACT_READY=1
  fi
elif [[ -d "$APP_DIR/frontend/build" ]]; then
  FRONTEND_ARTIFACT_READY=1
fi

if [[ "$EXISTING_FRONTEND_HASH" != "$FRONTEND_HASH" || "$FRONTEND_ARTIFACT_READY" -ne 1 ]]; then
  build_frontend || exit $? # Required for the "pnpm run preview" command of playwright.config.ts
  printf '%s\n' "$FRONTEND_HASH" >"$FRONTEND_HASH_FILE" || exit $?
fi

run_tests
