#!/usr/bin/env bats
#
# 1Password guards in compose.sh and compose_autoupdate.sh.
#
# docker, logger and the 1Password helpers are stub executables on PATH; no
# real Docker, 1Password CLI or token is used.
#

load '../bats_setup.bash'

SCRIPTS_DIR="$BATS_TEST_DIRNAME/../../source/compose.manager/scripts"
COMPOSE_SCRIPT="$SCRIPTS_DIR/compose.sh"
AUTOUPDATE_SCRIPT="$SCRIPTS_DIR/compose_autoupdate.sh"

FAKE_TOKEN="ops_FAKE_TEST_TOKEN_never_real_0123456789"
FAKE_SECRET="resolved-grafana-secret-value"

test_setup() {
    # Use stub executables instead of the framework's exported shell functions,
    # so programs started by other programs (env, op-secure) see them too.
    unset -f docker logger notify 2>/dev/null || true

    STUB_BIN="$TEST_TEMP_DIR/bin"
    mkdir -p "$STUB_BIN"
    export DOCKER_LOG="$TEST_TEMP_DIR/docker.log"
    export LOGGER_LOG="$TEST_TEMP_DIR/logger.log"
    : > "$DOCKER_LOG"
    : > "$LOGGER_LOG"

    cat > "$STUB_BIN/docker" <<'EOF'
#!/bin/bash
# Record the arguments and the 1Password-related environment of each call.
{
    printf 'ARGS:%s\n' "$*"
    printf 'ENV_GRAFANA_MCP_TOKEN:%s\n' "${GRAFANA_MCP_TOKEN-<unset>}"
    printf 'ENV_OP_SERVICE_ACCOUNT_TOKEN:%s\n' "${OP_SERVICE_ACCOUNT_TOKEN-<unset>}"
} >> "$DOCKER_LOG"
exit "${DOCKER_STUB_EXIT:-0}"
EOF
    cat > "$STUB_BIN/logger" <<'EOF'
#!/bin/bash
printf '%s\n' "$*" >> "$LOGGER_LOG"
EOF
    chmod +x "$STUB_BIN/docker" "$STUB_BIN/logger"
    export PATH="$STUB_BIN:$PATH"

    export COMPOSE_LOCK_TIMEOUT=2
    export COMPOSE_OP_SECURE_BIN="$TEST_TEMP_DIR/op/op-secure"
    export COMPOSE_OP_TOKEN_FILE="$TEST_TEMP_DIR/run/service-account-token"
    export COMPOSE_MANAGER_CFG_FILE="$TEST_TEMP_DIR/compose.manager.cfg"
    : > "$COMPOSE_MANAGER_CFG_FILE"
}

# Install a fake op-secure that emulates `op run --env-file=F -- cmd...`:
# resolves op:// values from F using $OP_FIXTURES (ref<TAB>value lines),
# fails like op when a reference is unknown, and exports a fake token to the
# child so tests can prove it is stripped.
install_fake_op() {
    mkdir -p "$(dirname "$COMPOSE_OP_SECURE_BIN")"
    export OP_FIXTURES="$TEST_TEMP_DIR/op/fixtures.tsv"
    export OP_CALL_LOG="$TEST_TEMP_DIR/op/calls.log"
    : > "$OP_FIXTURES"
    : > "$OP_CALL_LOG"
    cat > "$COMPOSE_OP_SECURE_BIN" <<'EOF'
#!/bin/bash
printf '%s\n' "$*" >> "$OP_CALL_LOG"
export OP_SERVICE_ACCOUNT_TOKEN="$FAKE_TOKEN_FOR_STUB"
case "$1" in
  whoami)
    [ "${OP_STUB_AUTH_FAIL:-0}" = "1" ] && { echo "[ERROR] authentication failed" >&2; exit 1; }
    echo "User Type: SERVICE_ACCOUNT"; exit 0 ;;
  run) shift ;;
  *) echo "unsupported stub call" >&2; exit 2 ;;
esac
env_file=""
while [ $# -gt 0 ]; do
  case "$1" in
    --env-file=*) env_file="${1#--env-file=}"; shift ;;
    --) shift; break ;;
    *) shift ;;
  esac
done
[ "${OP_STUB_AUTH_FAIL:-0}" = "1" ] && { echo "[ERROR] authentication failed" >&2; exit 1; }
while IFS= read -r line || [ -n "$line" ]; do
  case "$line" in ''|'#'*) continue ;; esac
  key="${line%%=*}"; value="${line#*=}"
  case "$value" in
    op://*)
      resolved=$(awk -F'\t' -v ref="$value" '$1 == ref { print $2; found=1 } END { exit !found }' "$OP_FIXTURES") || {
        echo "[ERROR] could not resolve secret reference for $key" >&2; exit 1; }
      export "$key=$resolved" ;;
  esac
done < "$env_file"
exec "$@"
EOF
    chmod +x "$COMPOSE_OP_SECURE_BIN"
    export FAKE_TOKEN_FOR_STUB="$FAKE_TOKEN"
}

unlock_op() {
    mkdir -p "$(dirname "$COMPOSE_OP_TOKEN_FILE")"
    printf '%s' "$FAKE_TOKEN" > "$COMPOSE_OP_TOKEN_FILE"
    chmod 600 "$COMPOSE_OP_TOKEN_FILE"
}

create_sitespeed_stack() {
    local dir="$TEST_TEMP_DIR/sitespeedio"
    mkdir -p "$dir"
    cat > "$dir/compose.yaml" <<'EOF'
services:
  grafana-mcp:
    image: grafana/mcp-grafana:latest
    environment:
      GRAFANA_SERVICE_ACCOUNT_TOKEN: ${GRAFANA_MCP_TOKEN}
      MCP_GRAFANA_SERVER_TOKEN: ${GRAFANA_MCP_SERVER_TOKEN}
EOF
    cat > "$dir/.env" <<'EOF'
GRAFANA_MCP_TOKEN=op://Homelab Secrets/Sitespeed - Grafana MCP/GRAFANA_MCP_TOKEN
GRAFANA_MCP_SERVER_TOKEN=op://Homelab Secrets/Sitespeed - Grafana MCP/GRAFANA_MCP_SERVER_TOKEN
EOF
    echo "$dir"
}

create_ordinary_stack() {
    local dir="$TEST_TEMP_DIR/paperless"
    mkdir -p "$dir"
    printf 'services:\n  app:\n    image: paperless\n' > "$dir/compose.yaml"
    printf 'DB_PASS=plain\n' > "$dir/.env"
    echo "$dir"
}

docker_called_with() {
    grep -q "^ARGS:.*$1" "$DOCKER_LOG"
}

# Explicit negative assertions: a bare `! cmd` does not fail a Bats test.
docker_not_called_with() {
    if grep -q "^ARGS:.*$1" "$DOCKER_LOG"; then
        echo "docker was unexpectedly called with: $1"
        cat "$DOCKER_LOG"
        return 1
    fi
}

file_not_contains() {
    if [ -f "$1" ] && grep -qF -- "$2" "$1"; then
        echo "$1 unexpectedly contains: $2"
        return 1
    fi
}

output_not_contains() {
    if [[ "$output" == *"$1"* ]]; then
        echo "output unexpectedly contains: $1"
        return 1
    fi
}

# ============================================================
# Shared helpers (common.sh)
# ============================================================

@test "onepassword_state reports unavailable, locked and unlocked" {
    # shellcheck source=/dev/null
    source "$SCRIPTS_DIR/common.sh"
    [ "$(onepassword_state)" = "unavailable" ]
    install_fake_op
    [ "$(onepassword_state)" = "locked" ]
    unlock_op
    [ "$(onepassword_state)" = "unlocked" ]
}

@test "onepassword_reference_files ignores comments and ordinary files" {
    # shellcheck source=/dev/null
    source "$SCRIPTS_DIR/common.sh"
    printf '# X=op://Vault/Item/field\nY=plain\n' > "$TEST_TEMP_DIR/commented.env"
    printf 'X=op://Vault/Item/field\n' > "$TEST_TEMP_DIR/ref.env"
    run onepassword_reference_files "$TEST_TEMP_DIR/commented.env" "$TEST_TEMP_DIR/ref.env" "$TEST_TEMP_DIR/missing.env"
    assert_success
    [ "$output" = "$TEST_TEMP_DIR/ref.env" ]
}

# ============================================================
# compose.sh
# ============================================================

@test "ordinary project up still runs docker compose up (regression)" {
    local dir
    dir=$(create_ordinary_stack)
    run bash "$COMPOSE_SCRIPT" -c up -p paperless -f "$dir/compose.yaml" -e "$dir/.env" -s "$dir"
    assert_success
    docker_called_with "compose --env-file $dir/.env -f $dir/compose.yaml -p paperless up -d"
}

@test "up is blocked for a 1Password project detected from its files" {
    local dir
    dir=$(create_sitespeed_stack)
    run bash "$COMPOSE_SCRIPT" -c up -p sitespeedio -f "$dir/compose.yaml" -e "$dir/.env" -s "$dir"
    [ "$status" -eq 78 ]
    assert_output_contains "1Password"
    docker_not_called_with " up"
    assert_file_contains "$dir/last_result.json" '"result":"failed"'
}

@test "up is blocked when the caller flags the project as 1Password-managed" {
    local dir
    dir=$(create_ordinary_stack)
    run bash "$COMPOSE_SCRIPT" -c up -p paperless -f "$dir/compose.yaml" --op-managed -s "$dir"
    [ "$status" -eq 78 ]
    docker_not_called_with " up"
}

@test "update is blocked before pulling for a 1Password project" {
    local dir
    dir=$(create_sitespeed_stack)
    run bash "$COMPOSE_SCRIPT" -c update -p sitespeedio -f "$dir/compose.yaml" -e "$dir/.env" -s "$dir"
    [ "$status" -eq 78 ]
    docker_not_called_with " pull"
    docker_not_called_with " up"
}

@test "update and up with default file discovery are also guarded" {
    local dir
    dir=$(create_sitespeed_stack)
    run bash "$COMPOSE_SCRIPT" -c up -p sitespeedio -w "$dir" -s "$dir"
    [ "$status" -eq 78 ]
    docker_not_called_with " up"
}

@test "logs, stop, down and pull keep working for a locked 1Password project" {
    local dir
    dir=$(create_sitespeed_stack)
    install_fake_op
    for cmd in logs stop down pull; do
        run bash "$COMPOSE_SCRIPT" -c "$cmd" -p sitespeedio -f "$dir/compose.yaml" -e "$dir/.env" -s "$dir"
        assert_success
    done
    docker_called_with "-p sitespeedio logs -f"
    docker_called_with "-p sitespeedio stop"
    docker_called_with "-p sitespeedio down"
    docker_called_with "-p sitespeedio pull --ignore-buildable"
    docker_not_called_with " up"
}

@test "autostart fallback starts existing containers without recreating" {
    local dir
    dir=$(create_sitespeed_stack)
    run bash "$COMPOSE_SCRIPT" -c up -p sitespeedio -f "$dir/compose.yaml" -e "$dir/.env" -s "$dir" \
        --op-env-file "$dir/.env" --op-locked-start-existing --recreate
    assert_success
    docker_called_with "-p sitespeedio start"
    docker_not_called_with " up"
    docker_not_called_with "force-recreate"
}

@test "autostart fallback reports failure when no containers exist" {
    local dir
    dir=$(create_sitespeed_stack)
    export DOCKER_STUB_EXIT=1
    run bash "$COMPOSE_SCRIPT" -c up -p sitespeedio -f "$dir/compose.yaml" -e "$dir/.env" -s "$dir" \
        --op-env-file "$dir/.env" --op-locked-start-existing
    assert_failure
    docker_not_called_with " up"
}

@test "blocked output and logs contain no secret values or token" {
    local dir
    dir=$(create_sitespeed_stack)
    install_fake_op
    unlock_op
    run bash "$COMPOSE_SCRIPT" -c up -p sitespeedio -f "$dir/compose.yaml" -e "$dir/.env" -s "$dir" --debug
    output_not_contains "$FAKE_TOKEN"
    output_not_contains "$FAKE_SECRET"
    file_not_contains "$LOGGER_LOG" "$FAKE_TOKEN"
    file_not_contains "$dir/last_result.json" "$FAKE_TOKEN"
}

# ============================================================
# compose_autoupdate.sh
# ============================================================

@test "auto-update skips a 1Password project before pulling" {
    local dir
    dir=$(create_sitespeed_stack)
    COMPOSE_FILE_LIST="$dir/compose.yaml" COMPOSE_ENV_FILE="$dir/.env" \
        run bash "$AUTOUPDATE_SCRIPT" sitespeedio
    [ "$status" -eq 78 ]
    docker_not_called_with " pull"
    docker_not_called_with " up"
}

@test "auto-update skips when the caller passes a 1Password env file" {
    local dir
    dir=$(create_ordinary_stack)
    COMPOSE_FILE_LIST="$dir/compose.yaml" COMPOSE_ONEPASSWORD_ENV_FILE="$dir/.env" \
        run bash "$AUTOUPDATE_SCRIPT" paperless
    [ "$status" -eq 78 ]
    docker_not_called_with " pull"
}

@test "auto-update still pulls ordinary projects (regression)" {
    local dir
    dir=$(create_ordinary_stack)
    COMPOSE_FILE_LIST="$dir/compose.yaml" COMPOSE_ENV_FILE="$dir/.env" \
        run bash "$AUTOUPDATE_SCRIPT" paperless
    assert_success
    docker_called_with "-p paperless pull --ignore-buildable"
}

# ============================================================
# Phase 2: secret-aware deployment
# ============================================================

add_fixture() {
    printf '%s\t%s\n' "$1" "$2" >> "$OP_FIXTURES"
}

add_sitespeed_fixtures() {
    add_fixture "op://Homelab Secrets/Sitespeed - Grafana MCP/GRAFANA_MCP_TOKEN" "$FAKE_SECRET"
    add_fixture "op://Homelab Secrets/Sitespeed - Grafana MCP/GRAFANA_MCP_SERVER_TOKEN" "resolved-server-token"
}

# The docker log line block (ARGS + ENV lines) for the first call matching $1.
docker_call_env() {
    awk -v pat="$1" '/^ARGS:/ { show = ($0 ~ pat) } show' "$DOCKER_LOG"
}

@test "unlocked: up resolves secrets for docker compose only and strips the token" {
    local dir
    dir=$(create_sitespeed_stack)
    install_fake_op
    unlock_op
    add_sitespeed_fixtures
    run bash "$COMPOSE_SCRIPT" -c up -p sitespeedio -f "$dir/compose.yaml" -e "$dir/.env" -s "$dir" \
        --op-env-file "$dir/.env" --debug
    assert_success
    assert_output_contains "Resolving 1Password secrets"
    docker_called_with "compose --env-file $dir/.env -f $dir/compose.yaml -p sitespeedio up -d"
    [ "$(docker_call_env ' up ' | grep '^ENV_GRAFANA_MCP_TOKEN:')" = "ENV_GRAFANA_MCP_TOKEN:$FAKE_SECRET" ]
    [ "$(docker_call_env ' up ' | grep '^ENV_OP_SERVICE_ACCOUNT_TOKEN:')" = "ENV_OP_SERVICE_ACCOUNT_TOKEN:<unset>" ]
    grep -q -- "whoami" "$OP_CALL_LOG"
    grep -q -- "run --env-file=$dir/.env -- true" "$OP_CALL_LOG"
    output_not_contains "$FAKE_SECRET"
    output_not_contains "$FAKE_TOKEN"
    file_not_contains "$LOGGER_LOG" "$FAKE_SECRET"
    file_not_contains "$LOGGER_LOG" "$FAKE_TOKEN"
    assert_file_contains "$dir/last_result.json" '"result":"success"'
}

@test "unlocked: update pulls without secrets and recreates with them" {
    local dir
    dir=$(create_sitespeed_stack)
    install_fake_op
    unlock_op
    add_sitespeed_fixtures
    run bash "$COMPOSE_SCRIPT" -c update -p sitespeedio -f "$dir/compose.yaml" -e "$dir/.env" -s "$dir" \
        --op-env-file "$dir/.env" --build
    assert_success
    [ "$(docker_call_env ' pull' | grep '^ENV_GRAFANA_MCP_TOKEN:')" = "ENV_GRAFANA_MCP_TOKEN:<unset>" ]
    docker_called_with "-p sitespeedio up -d --build"
    [ "$(docker_call_env ' up -d' | grep '^ENV_GRAFANA_MCP_TOKEN:')" = "ENV_GRAFANA_MCP_TOKEN:$FAKE_SECRET" ]
}

@test "unlocked: compose flags, profiles and paths with spaces are preserved" {
    local dir="$TEST_TEMP_DIR/My Stacks/site speed"
    mkdir -p "$dir"
    cp "$(create_sitespeed_stack)/compose.yaml" "$dir/compose.yaml"
    cp "$TEST_TEMP_DIR/sitespeedio/.env" "$dir/.env"
    printf 'services:\n  grafana-mcp:\n    labels:\n      a: b\n' > "$dir/compose.override.yaml"
    install_fake_op
    unlock_op
    add_sitespeed_fixtures
    run bash "$COMPOSE_SCRIPT" -c up -p sitespeedio -f "$dir/compose.yaml" -f "$dir/compose.override.yaml" \
        -e "$dir/.env" -g monitoring -s "$dir" --op-env-file "$dir/.env" \
        --recreate --remove-orphans --wait --wait-timeout 45
    assert_success
    docker_called_with "compose --env-file $dir/.env -f $dir/compose.yaml -f $dir/compose.override.yaml --profile monitoring -p sitespeedio up --force-recreate --remove-orphans --wait --wait-timeout 45 -d"
    [ "$(docker_call_env ' up ' | grep '^ENV_GRAFANA_MCP_TOKEN:')" = "ENV_GRAFANA_MCP_TOKEN:$FAKE_SECRET" ]
}

@test "unlocked: secret lookup failure blocks before any container change" {
    local dir
    dir=$(create_sitespeed_stack)
    install_fake_op
    unlock_op
    # No fixtures: every reference fails to resolve.
    run bash "$COMPOSE_SCRIPT" -c update -p sitespeedio -f "$dir/compose.yaml" -e "$dir/.env" -s "$dir" \
        --op-env-file "$dir/.env"
    [ "$status" -eq 78 ]
    assert_output_contains "could not be resolved"
    assert_output_contains "could not resolve secret reference for GRAFANA_MCP_TOKEN"
    docker_not_called_with " pull"
    docker_not_called_with " up"
}

@test "unlocked: authentication failure blocks deployment" {
    local dir
    dir=$(create_sitespeed_stack)
    install_fake_op
    unlock_op
    add_sitespeed_fixtures
    OP_STUB_AUTH_FAIL=1 run bash "$COMPOSE_SCRIPT" -c up -p sitespeedio -f "$dir/compose.yaml" -e "$dir/.env" \
        -s "$dir" --op-env-file "$dir/.env"
    [ "$status" -eq 78 ]
    assert_output_contains "could not authenticate"
    docker_not_called_with " up"
}

@test "locked: deployment is blocked with op-unlock guidance" {
    local dir
    dir=$(create_sitespeed_stack)
    install_fake_op
    run bash "$COMPOSE_SCRIPT" -c up -p sitespeedio -f "$dir/compose.yaml" -e "$dir/.env" -s "$dir" \
        --op-env-file "$dir/.env"
    [ "$status" -eq 78 ]
    assert_output_contains "Unlock 1Password on Unraid using op-unlock before deploying."
    docker_not_called_with " up"
    [ ! -s "$OP_CALL_LOG" ]
}

@test "no CLI installed: deployment is blocked with installation guidance" {
    local dir
    dir=$(create_sitespeed_stack)
    unlock_op
    run bash "$COMPOSE_SCRIPT" -c up -p sitespeedio -f "$dir/compose.yaml" -e "$dir/.env" -s "$dir" \
        --op-env-file "$dir/.env"
    [ "$status" -eq 78 ]
    assert_output_contains "op-secure"
    assert_output_contains "Install the 1Password CLI"
    docker_not_called_with " up"
}

@test "setting off: deployment is blocked even when unlocked" {
    local dir
    dir=$(create_sitespeed_stack)
    install_fake_op
    unlock_op
    add_sitespeed_fixtures
    echo 'ONEPASSWORD_SECRET_INJECTION="false"' > "$COMPOSE_MANAGER_CFG_FILE"
    run bash "$COMPOSE_SCRIPT" -c up -p sitespeedio -f "$dir/compose.yaml" -e "$dir/.env" -s "$dir" \
        --op-env-file "$dir/.env"
    [ "$status" -eq 78 ]
    assert_output_contains "turned off"
    docker_not_called_with " up"
}

@test "unlocked: literal op:// in compose YAML is never deployed" {
    local dir
    dir=$(create_sitespeed_stack)
    printf 'services:\n  grafana-mcp:\n    environment:\n      X: op://Vault/Item/field\n' > "$dir/compose.override.yaml"
    install_fake_op
    unlock_op
    add_sitespeed_fixtures
    run bash "$COMPOSE_SCRIPT" -c up -p sitespeedio -f "$dir/compose.yaml" -f "$dir/compose.override.yaml" \
        -e "$dir/.env" -s "$dir" --op-env-file "$dir/.env"
    [ "$status" -eq 78 ]
    docker_not_called_with " up"
}

@test "unlocked: env file mismatch between compose and op run is refused" {
    local dir
    dir=$(create_sitespeed_stack)
    printf 'OTHER=plain\n' > "$dir/other.env"
    install_fake_op
    unlock_op
    add_sitespeed_fixtures
    run bash "$COMPOSE_SCRIPT" -c up -p sitespeedio -f "$dir/compose.yaml" -e "$dir/.env" -s "$dir" \
        --op-env-file "$dir/other.env"
    [ "$status" -eq 78 ]
    docker_not_called_with " up"
}

@test "autostart: unlocked stacks are deployed normally, not just started" {
    local dir
    dir=$(create_sitespeed_stack)
    install_fake_op
    unlock_op
    add_sitespeed_fixtures
    run bash "$COMPOSE_SCRIPT" -c up -p sitespeedio -f "$dir/compose.yaml" -e "$dir/.env" -s "$dir" \
        --op-env-file "$dir/.env" --op-locked-start-existing
    assert_success
    docker_called_with "-p sitespeedio up -d"
    docker_not_called_with "-p sitespeedio start"
}

@test "autostart: lookup failure falls back to starting existing containers" {
    local dir
    dir=$(create_sitespeed_stack)
    install_fake_op
    unlock_op
    run bash "$COMPOSE_SCRIPT" -c up -p sitespeedio -f "$dir/compose.yaml" -e "$dir/.env" -s "$dir" \
        --op-env-file "$dir/.env" --op-locked-start-existing
    assert_success
    docker_called_with "-p sitespeedio start"
    docker_not_called_with " up"
}

@test "auto-update: unlocked stack pulls plainly and recreates with secrets" {
    local dir
    dir=$(create_sitespeed_stack)
    install_fake_op
    unlock_op
    add_sitespeed_fixtures
    # Make the digest comparison see a change so `up -d` runs.
    cat > "$STUB_BIN/docker" <<'STUB'
#!/bin/bash
{
    printf 'ARGS:%s\n' "$*"
    printf 'ENV_GRAFANA_MCP_TOKEN:%s\n' "${GRAFANA_MCP_TOKEN-<unset>}"
    printf 'ENV_OP_SERVICE_ACCOUNT_TOKEN:%s\n' "${OP_SERVICE_ACCOUNT_TOKEN-<unset>}"
} >> "$DOCKER_LOG"
case "$*" in
  *"config --images"*) echo "grafana/mcp-grafana:latest" ;;
  "image inspect"*) if grep -q 'ARGS:.* pull' "$DOCKER_LOG"; then echo "sha256:new"; else echo "sha256:old"; fi ;;
  *" ps -q"*) echo "abc123" ;;
esac
exit 0
STUB
    chmod +x "$STUB_BIN/docker"
    COMPOSE_FILE_LIST="$dir/compose.yaml" COMPOSE_ENV_FILE="$dir/.env" COMPOSE_ONEPASSWORD_ENV_FILE="$dir/.env" \
        run bash "$AUTOUPDATE_SCRIPT" sitespeedio
    assert_success
    [ "$(docker_call_env ' pull' | grep '^ENV_GRAFANA_MCP_TOKEN:')" = "ENV_GRAFANA_MCP_TOKEN:<unset>" ]
    docker_called_with "-p sitespeedio up -d"
    [ "$(docker_call_env ' up -d' | grep '^ENV_GRAFANA_MCP_TOKEN:')" = "ENV_GRAFANA_MCP_TOKEN:$FAKE_SECRET" ]
    [ "$(docker_call_env ' up -d' | grep '^ENV_OP_SERVICE_ACCOUNT_TOKEN:')" = "ENV_OP_SERVICE_ACCOUNT_TOKEN:<unset>" ]
    output_not_contains "$FAKE_SECRET"
}

@test "auto-update: locked stack is skipped before pulling" {
    local dir
    dir=$(create_sitespeed_stack)
    install_fake_op
    COMPOSE_FILE_LIST="$dir/compose.yaml" COMPOSE_ENV_FILE="$dir/.env" COMPOSE_ONEPASSWORD_ENV_FILE="$dir/.env" \
        run bash "$AUTOUPDATE_SCRIPT" sitespeedio
    [ "$status" -eq 78 ]
    assert_output_contains "op-unlock"
    docker_not_called_with " pull"
}

@test "auto-update: default .env next to the compose file is checked" {
    local dir
    dir=$(create_sitespeed_stack)
    install_fake_op
    unlock_op
    add_sitespeed_fixtures
    COMPOSE_FILE_LIST="$dir/compose.yaml" run bash "$AUTOUPDATE_SCRIPT" sitespeedio
    [ "$status" -eq 78 ]
    docker_not_called_with " pull"
}
