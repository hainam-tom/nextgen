#!/usr/bin/env bash
# shellcheck shell=bash

set -euo pipefail

is_truthy() {
  local value="${1:-}"
  case "${value,,}" in
    1|y|yes|true|on) return 0 ;;
  esac
  return 1
}

is_falsy() {
  local value="${1:-}"
  case "${value,,}" in
    0|n|no|false|off) return 0 ;;
  esac
  return 1
}

maybe_sync_repository() {
  local repo_root="$1"
  local skip="${INSTALL_SKIP_SYNC:-}"
  if is_truthy "$skip"; then
    return
  fi
  local repo_url="${INSTALL_REPO_URL:-}"
  local remote="${INSTALL_REPO_REMOTE:-origin}"
  local branch="${INSTALL_REPO_BRANCH:-}"
  if [[ ! -d "$repo_root/.git" ]]; then
    if [[ -n "$repo_url" ]]; then
      echo "Installer repository sync requested but $repo_root is not a git checkout; skipping." >&2
    fi
    return
  fi
  if ! command -v git >/dev/null 2>&1; then
    if [[ -n "$repo_url" ]]; then
      echo "git not available; skipping repository sync." >&2
    fi
    return
  fi
  (
    cd "$repo_root"
    local current_branch
    current_branch=$(git rev-parse --abbrev-ref HEAD 2>/dev/null || echo "")
    if [[ -z "$branch" ]]; then
      branch="$current_branch"
    fi
    if [[ -z "$branch" ]]; then
      branch="main"
    fi
    if [[ -n "$current_branch" && "$current_branch" != "$branch" ]]; then
      echo "Skipping repository sync because current branch '$current_branch' differs from '$branch'." >&2
      return
    fi
    if [[ -n "$repo_url" ]]; then
      if git remote get-url "$remote" >/dev/null 2>&1; then
        git remote set-url "$remote" "$repo_url" >/dev/null 2>&1 || true
      else
        git remote add "$remote" "$repo_url" >/dev/null 2>&1 || true
      fi
    fi
    echo "Ensuring repository is up to date from ${remote}/${branch}..."
    if ! git fetch "$remote" "$branch" >/dev/null 2>&1; then
      echo "Warning: unable to fetch ${remote}/${branch}; continuing with local files." >&2
      return
    fi
    if ! git merge --ff-only FETCH_HEAD >/dev/null 2>&1; then
      echo "Warning: local checkout has diverged from ${remote}/${branch}; please update manually." >&2
      return
    fi
    echo "Repository updated to latest ${remote}/${branch}."
  )
}

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

maybe_get_public_ip() {
  if command -v curl >/dev/null 2>&1; then
    local ip
    if ip=$(curl -fsS --max-time 6 https://ifconfig.co/ip 2>/dev/null); then
      ip=$(printf '%s' "$ip" | tr -d '\r\n')
      if [[ -n "$ip" ]]; then
        printf '%s' "$ip"
        return 0
      fi
    fi
  fi
  return 1
}

format_origin() {
  local scheme="$1"
  local host="$2"
  local port="$3"
  python3 - "$scheme" "$host" "$port" <<'PY'
import sys
scheme, host, port = sys.argv[1], sys.argv[2], sys.argv[3]
host = host.strip()
if not host:
    print("")
    sys.exit(0)
try:
    port = int(port)
except ValueError:
    print("")
    sys.exit(0)
if scheme not in {"http", "https"}:
    print("")
    sys.exit(0)
default = 443 if scheme == "https" else 80
suffix = "" if port == default else f":{port}"
print(f"{scheme}://{host}{suffix}")
PY
}

build_allowed_origins() {
  local api_port="$1"
  local force_tls="$2"
  local public_base="$3"
  local fallback_host="$4"
  local domain="$5"
  local public_port="$6"
  python3 - "$api_port" "$force_tls" "$public_base" "$fallback_host" "$domain" "$public_port" <<'PY'
import sys
api_port = int(sys.argv[1])
force_tls = sys.argv[2] == "1"
public_base = sys.argv[3]
fallback_host = sys.argv[4]
domain = sys.argv[5]
public_port = int(sys.argv[6])
scheme = "https" if force_tls else "http"

def origin(scheme, host, port):
    host = host.strip()
    if not host:
        return ""
    default = 443 if scheme == "https" else 80
    suffix = "" if port == default else f":{port}"
    return f"{scheme}://{host}{suffix}"

origins = []
for local_scheme in ("https", "http"):
    origins.append(origin(local_scheme, "127.0.0.1", api_port))

if fallback_host:
    origins.append(origin(scheme, fallback_host, api_port))

if domain:
    origins.append(origin(scheme, domain, public_port))
    if not domain.startswith("www."):
        origins.append(origin(scheme, "www." + domain, public_port))

if public_base:
    from urllib.parse import urlparse
    parsed = urlparse(public_base)
    if parsed.scheme and parsed.hostname:
        port = parsed.port or (443 if parsed.scheme == "https" else 80)
        origins.append(origin(parsed.scheme, parsed.hostname, port))

clean = []
seen = set()
for item in origins:
    if item and item not in seen:
        seen.add(item)
        clean.append(item)
print(",".join(clean))
PY
}

write_env_file() {
  local repo_root="$1"
  local port="$2"
  local force_tls="$3"
  local public_base="$4"
  local fallback_host="$5"
  local domain="$6"
  local public_port="$7"
  local cert_path="$8"
  local key_path="$9"
  local le_email="${10:-}"
  local env_path="$repo_root/admin/.env"
  local origins
  origins=$(build_allowed_origins "$port" "$force_tls" "$public_base" "$fallback_host" "$domain" "$public_port")
  if [[ -f "$env_path" ]]; then
    local backup_path="${env_path}.bak.$(date +%s)"
    cp "$env_path" "$backup_path"
    echo "Existing .env backed up to $(basename "$backup_path")."
  fi
  {
    printf 'API_HOST=0.0.0.0\n'
    printf 'API_PORT=%s\n' "$port"
    printf 'PUBLIC_PORT=%s\n' "$public_port"
    printf 'FORCE_TLS=%s\n' "$force_tls"
    printf 'PUBLIC_BASE_URL=%s\n' "$public_base"
    printf 'PUBLIC_DOMAIN=%s\n' "$domain"
    printf 'PUBLIC_FALLBACK_HOST=%s\n' "$fallback_host"
    printf 'ALLOWED_ORIGINS=%s\n' "$origins"
    printf 'PRODUCT_BACKUPS=3\n'
    printf 'TRUST_PROXY_HEADERS=1\n'
    if [[ -n "$cert_path" ]]; then
      printf 'TLS_CERT_FILE=%s\n' "$cert_path"
    fi
    if [[ -n "$key_path" ]]; then
      printf 'TLS_KEY_FILE=%s\n' "$key_path"
    fi
    if [[ -n "$le_email" ]]; then
      printf 'LETS_ENCRYPT_EMAIL=%s\n' "$le_email"
    fi
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

obtain_letsencrypt_cert() {
  local domain="$1"
  local email="$2"
  if ! command -v certbot >/dev/null 2>&1; then
    echo "certbot not installed; skipping automatic certificate request." >&2
    return 1
  fi
  echo "Running certbot for $domain..."
  local args=(certbot certonly --standalone --agree-tos --non-interactive --preferred-challenges http -d "$domain")
  if is_truthy "${LETS_ENCRYPT_STAGING:-}"; then
    args+=(--staging)
  fi
  if [[ -n "$email" ]]; then
    args+=(--email "$email")
  else
    args+=(--register-unsafely-without-email)
  fi
  if "${args[@]}"; then
    return 0
  fi
  return 1
}

cloudflare_upsert_record() {
  local domain="$1"
  local ip="$2"
  local zone_id="$3"
  local token="$4"
  local proxied="$5"
  local proxied_flag="false"
  if [[ "$proxied" == "1" ]]; then
    proxied_flag="true"
  fi
  local headers=(-H "Authorization: Bearer $token" -H "Content-Type: application/json")

  local lookup
  if ! lookup=$(curl -fsS -X GET "https://api.cloudflare.com/client/v4/zones/${zone_id}/dns_records?type=A&name=${domain}" "${headers[@]}" 2>/dev/null); then
    return 1
  fi

  local record_id=""
  record_id=$(printf '%s' "$lookup" | python3 - <<'PY'
import json, sys
try:
    data = json.loads(sys.stdin.read() or '{}')
except json.JSONDecodeError:
    sys.exit(0)
for record in data.get('result', []):
    ident = record.get('id')
    if ident:
        print(ident)
        break
PY
  )

  local method="POST"
  local endpoint="https://api.cloudflare.com/client/v4/zones/${zone_id}/dns_records"
  if [[ -n "$record_id" ]]; then
    method="PUT"
    endpoint="${endpoint}/${record_id}"
  fi

  local payload
  payload=$(DOMAIN="$domain" IP="$ip" PROXIED="$proxied_flag" python3 - <<'PY'
import json, os
payload = {
    "type": "A",
    "name": os.environ["DOMAIN"],
    "content": os.environ["IP"],
    "ttl": 120,
    "proxied": os.environ["PROXIED"].lower() == "true",
}
print(json.dumps(payload))
PY
  )

  local response
  if ! response=$(curl -fsS -X "$method" "$endpoint" "${headers[@]}" --data "$payload" 2>/dev/null); then
    return 1
  fi

  if printf '%s' "$response" | python3 - <<'PY'
import json, sys
try:
    data = json.loads(sys.stdin.read() or '{}')
except json.JSONDecodeError:
    sys.exit(1)
sys.exit(0 if data.get('success') else 1)
PY
  then
    return 0
  fi
  return 1
}

configure_cloudflare_dns() {
  local domain="$1"
  echo
  if ! prompt_yes_no "Create or update a Cloudflare DNS A record for ${domain}? [y/N] " "n"; then
    return
  fi
  require_command curl

  local ip=""
  if ip=$(maybe_get_public_ip); then
    echo "Detected public IPv4: $ip"
  else
    echo "Could not automatically determine the public IPv4 address."
    printf "IPv4 address to assign: "
    read -r ip </dev/tty || ip=""
  fi
  if [[ -z "$ip" ]]; then
    echo "Skipping Cloudflare DNS update (no IP provided)."
    return
  fi

  local zone_default="${CLOUDFLARE_ZONE_ID:-}"
  local zone_prompt="Cloudflare Zone ID"
  if [[ -n "$zone_default" ]]; then
    zone_prompt+=" [$zone_default]"
  fi
  zone_prompt+=": "
  printf "%s" "$zone_prompt"
  local zone_id
  read -r zone_id </dev/tty || zone_id=""
  zone_id=${zone_id:-$zone_default}
  if [[ -z "$zone_id" ]]; then
    echo "Skipping Cloudflare DNS update (missing zone ID)."
    return
  fi

  local token_default="${CLOUDFLARE_API_TOKEN:-}"
  local token=""
  if [[ -n "$token_default" ]]; then
    echo "Using Cloudflare API token from environment."
    token="$token_default"
  else
    printf "Cloudflare API token (DNS edit scope): "
    read -r -s token </dev/tty || token=""
    echo
  fi
  if [[ -z "$token" ]]; then
    echo "Skipping Cloudflare DNS update (missing API token)."
    return
  fi

  local proxied=0
  local proxied_env="${CLOUDFLARE_PROXY_DEFAULT:-}"
  local proxied_prompt_suffix="[Y/n]"
  local proxied_default_answer="y"
  if is_falsy "$proxied_env"; then
    proxied_prompt_suffix="[y/N]"
    proxied_default_answer="n"
  elif is_truthy "$proxied_env"; then
    proxied_prompt_suffix="[Y/n]"
    proxied_default_answer="y"
  fi
  if prompt_yes_no "Proxy traffic through Cloudflare (orange cloud)? ${proxied_prompt_suffix} " "$proxied_default_answer"; then
    proxied=1
  fi

  if cloudflare_upsert_record "$domain" "$ip" "$zone_id" "$token" "$proxied"; then
    echo "Cloudflare DNS record for $domain is configured."
  else
    echo "Failed to configure Cloudflare DNS via API. Please update it manually."
  fi
}

run_install() {
  local script_dir="$1"
  local repo_root="$2"
  local shell_name="$3"
  local platform="${4:-linux}"

  echo "== Vendly deployment assistant (${shell_name}) =="
  maybe_sync_repository "$repo_root"
  require_command python3

  local default_port="${API_PORT:-7890}"
  if [[ ! "$default_port" =~ ^[0-9]+$ ]] || (( default_port < 1 || default_port > 65535 )); then
    default_port=7890
  fi
  local port
  port=$(prompt_port "$default_port")

  local fallback_default="${PUBLIC_FALLBACK_HOST:-127.0.0.1}"
  printf "Technician fallback hostname/IP [%s]: " "$fallback_default"
  local fallback_host
  read -r fallback_host </dev/tty || fallback_host=""
  fallback_host=${fallback_host:-$fallback_default}

  local preset_domain="${PUBLIC_DOMAIN:-}"
  preset_domain=$(printf '%s' "$preset_domain" | tr '[:upper:]' '[:lower:]')
  preset_domain=${preset_domain%.}
  preset_domain=${preset_domain//[[:space:]]/}

  local use_domain=0
  local domain=""
  if [[ -n "$preset_domain" ]]; then
    domain="$preset_domain"
    use_domain=1
    echo "Using preset domain from environment: $domain"
  fi
  if (( use_domain == 0 )); then
    if prompt_yes_no "Configure a custom domain name? [y/N] " "n"; then
      use_domain=1
    fi
  fi
  if (( use_domain == 1 )); then
    local domain_input=""
    while true; do
      if [[ -n "$domain" ]]; then
        printf "Domain (e.g. shop.example.com) [%s]: " "$domain"
      else
        printf "Domain (e.g. shop.example.com): "
      fi
      read -r domain_input </dev/tty || domain_input=""
      domain_input=${domain_input:-$domain}
      domain_input=$(printf '%s' "$domain_input" | tr '[:upper:]' '[:lower:]')
      domain_input=${domain_input%.}
      domain_input=${domain_input//[[:space:]]/}
      if [[ -z "$domain_input" ]]; then
        echo "Domain cannot be empty." >&2
        continue
      fi
      if [[ ! "$domain_input" =~ ^[a-z0-9.-]+$ ]]; then
        echo "Domain may only contain letters, numbers, dots, and hyphens." >&2
        continue
      fi
      domain="$domain_input"
      break
    done
    configure_cloudflare_dns "$domain"
  fi

  if [[ "$platform" == "macos" ]]; then
    echo
    echo "macOS prerequisites: ensure Xcode command line tools and Homebrew Python are installed if python3 is missing."
  fi

  echo
  echo "Checking external visibility..."
  check_port_forwarding "$port"

  local tls_mode="http"
  local scheme="http"
  local env_force_tls="${FORCE_TLS:-}"
  local preset_cert="${TLS_CERT_FILE:-}"
  local preset_key="${TLS_KEY_FILE:-}"
  local preset_le_email="${LETS_ENCRYPT_EMAIL:-}"
  local cert_path=""
  local key_path=""
  local le_email="$preset_le_email"
  local env_public_port="${PUBLIC_PORT:-}"
  local public_port="$port"
  if [[ -n "$env_public_port" && "$env_public_port" =~ ^[0-9]+$ ]]; then
    public_port="$env_public_port"
  fi

  local force_tls=0
  if is_truthy "$env_force_tls"; then
    force_tls=1
  fi

  if (( use_domain == 1 )); then
    echo
    echo "TLS configuration for $domain:"
    echo "  [1] Automatic Let's Encrypt certificate (recommended)"
    echo "  [2] Provide existing certificate paths"
    echo "  [3] Self-signed development certificate"
    echo "  [4] Disable HTTPS"
    local tls_choice_default="1"
    if [[ -n "$preset_cert" && -n "$preset_key" ]]; then
      tls_choice_default="2"
    elif is_falsy "$env_force_tls"; then
      tls_choice_default="4"
    fi
    printf "Select option [%s]: " "$tls_choice_default"
    local tls_choice
    read -r tls_choice </dev/tty || tls_choice=""
    tls_choice=${tls_choice:-$tls_choice_default}
    case "$tls_choice" in
      1)
        tls_mode="letsencrypt"
        force_tls=1
        ;;
      2)
        tls_mode="manual"
        force_tls=1
        ;;
      3)
        tls_mode="adhoc"
        force_tls=1
        ;;
      4)
        tls_mode="http"
        force_tls=0
        ;;
      *)
        echo "Unknown option; defaulting to Let's Encrypt."
        tls_mode="letsencrypt"
        force_tls=1
        ;;
    esac
  else
    local https_prompt_suffix="[Y/n]"
    local https_default_answer="y"
    if is_falsy "$env_force_tls"; then
      https_prompt_suffix="[y/N]"
      https_default_answer="n"
    fi
    if prompt_yes_no "Enable HTTPS with a self-signed certificate? ${https_prompt_suffix} " "$https_default_answer"; then
      tls_mode="adhoc"
      force_tls=1
    else
      tls_mode="http"
      force_tls=0
    fi
  fi

  if [[ "$force_tls" == "1" ]]; then
    scheme="https"
  fi

  if (( use_domain == 1 )); then
    local default_public_port="$public_port"
    if [[ -z "$default_public_port" || ! "$default_public_port" =~ ^[0-9]+$ ]]; then
      if [[ "$scheme" == "https" ]]; then
        default_public_port=443
      else
        default_public_port=80
      fi
    fi
    printf "External port clients will use for %s [%s]: " "$domain" "$default_public_port"
    local public_port_input
    read -r public_port_input </dev/tty || public_port_input=""
    public_port_input=${public_port_input:-$default_public_port}
    if [[ "$public_port_input" =~ ^[0-9]+$ ]] && (( public_port_input >= 1 && public_port_input <= 65535 )); then
      public_port=$public_port_input
    else
      echo "Invalid port supplied; using $default_public_port."
      public_port=$default_public_port
    fi
  else
    if [[ -z "$public_port" || ! "$public_port" =~ ^[0-9]+$ ]]; then
      public_port=$port
    fi
  fi

  if [[ "$tls_mode" == "letsencrypt" ]]; then
    cert_path=""
    key_path=""
    echo
    echo "Attempting to obtain a Let's Encrypt certificate (certbot must be installed and TCP/80 must be reachable)."
    local le_prompt="Email for Let's Encrypt expiry notices (optional)"
    if [[ -n "$preset_le_email" ]]; then
      printf "%s [%s]: " "$le_prompt" "$preset_le_email"
    else
      printf "%s: " "$le_prompt"
    fi
    local le_input=""
    read -r le_input </dev/tty || le_input=""
    le_input=${le_input:-$preset_le_email}
    le_email="$le_input"
    if obtain_letsencrypt_cert "$domain" "$le_email"; then
      local le_dir="/etc/letsencrypt/live/$domain"
      if [[ -d "$le_dir" ]]; then
        cert_path="$le_dir/fullchain.pem"
        key_path="$le_dir/privkey.pem"
        echo "Stored certificates in $le_dir."
      fi
    else
      echo "Let's Encrypt enrollment skipped or failed."
    fi
    if [[ -z "$cert_path" || -z "$key_path" ]]; then
      if prompt_yes_no "Provide certificate paths manually now? [Y/n] " "y"; then
        local cert_input=""
        local key_input=""
        while true; do
          local cert_prompt
          cert_prompt=$(printf "Certificate chain path (e.g. /etc/letsencrypt/live/%s/fullchain.pem)" "$domain")
          if [[ -n "$preset_cert" ]]; then
            cert_prompt+=" [$preset_cert]"
          fi
          printf "%s: " "$cert_prompt"
          read -r cert_input </dev/tty || cert_input=""
          cert_input=${cert_input:-$preset_cert}
          if [[ -z "$cert_input" ]]; then
            echo "Path cannot be empty." >&2
            continue
          fi
          if [[ ! -f "$cert_input" ]]; then
            echo "File not found: $cert_input" >&2
            cert_input=""
            continue
          fi
          local key_prompt
          key_prompt=$(printf "Private key path (e.g. /etc/letsencrypt/live/%s/privkey.pem)" "$domain")
          if [[ -n "$preset_key" ]]; then
            key_prompt+=" [$preset_key]"
          fi
          printf "%s: " "$key_prompt"
          read -r key_input </dev/tty || key_input=""
          key_input=${key_input:-$preset_key}
          if [[ -z "$key_input" ]]; then
            echo "Path cannot be empty." >&2
            continue
          fi
          if [[ ! -f "$key_input" ]]; then
            echo "File not found: $key_input" >&2
            key_input=""
            continue
          fi
          cert_path="$cert_input"
          key_path="$key_input"
          break
        done
      else
        echo "You can rerun the installer later to record certificate paths once available."
      fi
    fi
  elif [[ "$tls_mode" == "manual" ]]; then
    echo
    echo "Enter the paths to your existing certificate chain and private key."
    local cert_input=""
    local key_input=""
    while true; do
      local cert_prompt="Certificate chain path"
      if [[ -n "$preset_cert" ]]; then
        cert_prompt+=" [$preset_cert]"
      fi
      printf "%s: " "$cert_prompt"
      read -r cert_input </dev/tty || cert_input=""
      cert_input=${cert_input:-$preset_cert}
      if [[ -z "$cert_input" ]]; then
        echo "Path cannot be empty." >&2
        continue
      fi
      if [[ ! -f "$cert_input" ]]; then
        echo "File not found: $cert_input" >&2
        cert_input=""
        continue
      fi
      local key_prompt="Private key path"
      if [[ -n "$preset_key" ]]; then
        key_prompt+=" [$preset_key]"
      fi
      printf "%s: " "$key_prompt"
      read -r key_input </dev/tty || key_input=""
      key_input=${key_input:-$preset_key}
      if [[ -z "$key_input" ]]; then
        echo "Path cannot be empty." >&2
        continue
      fi
      if [[ ! -f "$key_input" ]]; then
        echo "File not found: $key_input" >&2
        key_input=""
        continue
      fi
      cert_path="$cert_input"
      key_path="$key_input"
      break
    done
  fi

  local public_base_url="${PUBLIC_BASE_URL:-}"
  if [[ -z "$public_base_url" ]]; then
    if (( use_domain == 1 )); then
      public_base_url=$(format_origin "$scheme" "$domain" "$public_port")
    else
      public_base_url=$(format_origin "$scheme" "$fallback_host" "$port")
    fi
  fi

  echo
  echo "Creating environment configuration..."
  write_env_file "$repo_root" "$port" "$force_tls" "$public_base_url" "$fallback_host" "$domain" "$public_port" "$cert_path" "$key_path" "$le_email"

  echo
  echo "Setting up Python environment..."
  create_virtualenv "$repo_root"

  local display_base="$public_base_url"
  if [[ -z "$display_base" ]]; then
    display_base=$(format_origin "$scheme" "$fallback_host" "$port")
  fi
  local dns_note=""
  if (( use_domain == 1 )); then
    dns_note="Remember to keep your DNS pointing at this host and renew Let's Encrypt certificates (e.g. via 'certbot renew')."
  fi

  cat <<EON

Installation complete.

Next steps:
  1. Activate the virtualenv:   source "$repo_root/.venv/bin/activate"
  2. Start the API:             python -m admin.app

The service will listen on ${display_base} (API port ${port}).
EON

  if [[ -n "$dns_note" ]]; then
    echo "$dns_note"
  fi
  echo "Remember to forward TCP port ${public_port} on your router if clients must reach it externally."
}
