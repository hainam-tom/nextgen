#!/usr/bin/env bash
# shellcheck shell=bash

set -euo pipefail

prompt_yes_no() {
  local prompt="$1"
  local default="$2"
  local reply
  while true; do
    printf "%s" "$prompt"
    read -r reply </dev/tty || reply=""
    reply=${reply:-$default}
    reply=$(printf "%s" "$reply" | tr '[:upper:]' '[:lower:]')
    case "$reply" in
      y|yes) return 0 ;;
      n|no) return 1 ;;
      *) echo "Please enter y or n." ;;
    esac
  done
}

require_command() {
  local cmd="$1"
  if ! command -v "$cmd" >/dev/null 2>&1; then
    echo "error: missing required command '$cmd'" >&2
    exit 1
  fi
}

prompt_port() {
  local default_port="$1"
  local port
  while true; do
    printf "Select API port [%s]: " "$default_port"
    read -r port </dev/tty || port=""
    port=${port:-$default_port}
    if [[ ! $port =~ ^[0-9]+$ ]] || (( port < 1 || port > 65535 )); then
      echo "Port must be a number between 1 and 65535." >&2
      continue
    fi
    if ! python3 - "$port" <<'PY'
import socket, sys
port = int(sys.argv[1])
sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
try:
    sock.bind(("0.0.0.0", port))
except OSError:
    sys.exit(1)
finally:
    sock.close()
PY
    then
      echo "Port $port appears to be in use. Please choose another." >&2
      continue
    fi
    echo "$port"
    return
  done
}

check_port_forwarding() {
  local port="$1"
  if ! command -v curl >/dev/null 2>&1; then
    echo "Skipped automatic port-forwarding check (curl not available)."
    return
  fi
  local response
  if ! response=$(curl -fsS --max-time 6 "https://ifconfig.co/port/${port}" 2>/dev/null); then
    echo "Skipped automatic port-forwarding check (unable to contact ifconfig.co)."
    return
  fi
  PORT_TO_CHECK="$port" printf '%s' "$response" | python3 - <<'PY'
import json, os, sys
raw = sys.stdin.read()
try:
    data = json.loads(raw or '{}')
except json.JSONDecodeError:
    print('Could not parse port checker response.')
    sys.exit(0)
port = data.get('port') or os.environ.get('PORT_TO_CHECK')
ip = data.get('ip', 'unknown')
reachable = data.get('reachable')
if reachable:
    print(f"Port {port} is reachable from the internet (public IP: {ip}).")
else:
    print(f"Port {port} is NOT reachable from the internet yet (public IP: {ip}).")
PY
}

write_env_file() {
  local repo_root="$1"
  local port="$2"
  local force_tls="$3"
  local public_host="$4"
  local scheme="http"
  if [[ "$force_tls" == "1" ]]; then
    scheme="https"
  fi
  local env_path="$repo_root/admin/.env"
  if [[ -f "$env_path" ]]; then
    local backup_path="${env_path}.bak.$(date +%s)"
    cp "$env_path" "$backup_path"
    echo "Existing .env backed up to $(basename "$backup_path")."
  fi
  local origins="https://127.0.0.1:${port},http://127.0.0.1:${port},${scheme}://${public_host}:${port}"
  {
    printf 'API_HOST=0.0.0.0\n'
    printf 'API_PORT=%s\n' "$port"
    printf 'FORCE_TLS=%s\n' "$force_tls"
    printf 'PUBLIC_BASE_URL=%s://%s:%s\n' "$scheme" "$public_host" "$port"
    printf 'ALLOWED_ORIGINS=%s\n' "$origins"
    printf 'PRODUCT_BACKUPS=3\n'
    printf 'TRUST_PROXY_HEADERS=1\n'
  } > "$env_path"
  echo "Wrote admin/.env with selected options."
}

create_virtualenv() {
  local repo_root="$1"
  if [[ ! -d "$repo_root/.venv" ]]; then
    python3 -m venv "$repo_root/.venv"
  fi
  "$repo_root/.venv/bin/python" -m pip install --upgrade pip >/dev/null
  "$repo_root/.venv/bin/python" -m pip install -r "$repo_root/admin/requirements.txt"
}

run_install() {
  local script_dir="$1"
  local repo_root="$2"
  local shell_name="$3"
  local platform="${4:-linux}"

  echo "== Vendly deployment assistant (${shell_name}) =="
  require_command python3
  local default_port="${API_PORT:-7890}"
  local port
  port=$(prompt_port "$default_port")

  local enable_tls=1
  if prompt_yes_no "Enable HTTPS with a self-signed certificate? [Y/n] " "y"; then
    enable_tls=1
  else
    enable_tls=0
  fi

  local default_host="${PUBLIC_HOST:-127.0.0.1}"
  printf "Public hostname for links [%s]: " "$default_host"
  local host
  read -r host </dev/tty || host=""
  host=${host:-$default_host}

  if [[ "$platform" == "macos" ]]; then
    echo
    echo "macOS prerequisites: ensure Xcode command line tools and Homebrew Python are installed if python3 is missing."
  fi

  echo
  echo "Checking external visibility..."
  check_port_forwarding "$port"

  echo
  echo "Creating environment configuration..."
  write_env_file "$repo_root" "$port" "$enable_tls" "$host"

  echo
  echo "Setting up Python environment..."
  create_virtualenv "$repo_root"

  cat <<EON

Installation complete.

Next steps:
  1. Activate the virtualenv:   source "$repo_root/.venv/bin/activate"
  2. Start the API:             python -m admin.app

The service will listen on ${host}:${port} via $( [[ $enable_tls -eq 1 ]] && echo HTTPS || echo HTTP ).
Remember to forward TCP port ${port} on your router if clients must reach it externally.
EON
}
