#!/usr/bin/env bash
# Run the piplyzer GitHub App locally: build the binary, create the App on first
# run, start the check server, open a Cloudflare Quick Tunnel, point the App
# webhook at that tunnel, and keep the two processes together. The tunnel URL
# changes whenever this script restarts, so the webhook is updated again each time.
set -euo pipefail

repo_root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
config_dir=${PIPLYZER_CONFIG_DIR:-"$repo_root/.piplyzer"}
# A relative config dir would resolve against wherever the caller stood, so
# make it absolute before anything runs from a different directory.
case "$config_dir" in
/*) ;;
*) config_dir="$PWD/$config_dir" ;;
esac
binary="$repo_root/piplyzer"
# Overridable so the runner can run beside another service on this machine.
port=${PIPLYZER_PORT:-8080}
setup_port=8081
api=https://api.github.com

for cmd in go cloudflared openssl curl; do
	if ! command -v "$cmd" >/dev/null 2>&1; then
		echo "piplyzer: $cmd is required" >&2
		exit 1
	fi
done

# Rebuild every run. A binary from yesterday would run yesterday's code, and a
# cached rebuild costs a second.
go build -C "$repo_root" -o "$binary" ./cmd/ppe

if [ ! -f "$config_dir/config.env" ]; then
	mkdir -p "$config_dir"
	chmod 700 "$config_dir"
	echo "piplyzer: creating the GitHub App"
	"$binary" setup --addr "127.0.0.1:${setup_port}" --config-dir "$config_dir"
	if [ ! -f "$config_dir/config.env" ]; then
		echo "piplyzer: setup did not write $config_dir/config.env" >&2
		exit 1
	fi
fi

set -a
# shellcheck disable=SC1091
. "$config_dir/config.env"
set +a

: "${PIPLYZER_APP_ID:?config.env is missing PIPLYZER_APP_ID}"
: "${PIPLYZER_WEBHOOK_SECRET:?config.env is missing PIPLYZER_WEBHOOK_SECRET}"
: "${PIPLYZER_APP_SLUG:?config.env is missing PIPLYZER_APP_SLUG}"

key="$config_dir/app.pem"
if [ ! -f "$key" ]; then
	echo "piplyzer: $key is missing" >&2
	exit 1
fi

b64url() {
	openssl base64 -A | tr '+/' '-_' | tr -d '='
}

app_jwt() {
	local now header payload signing sig
	now=$(date +%s)
	header=$(printf '%s' '{"alg":"RS256","typ":"JWT"}' | b64url)
	payload=$(printf '{"iat":%d,"exp":%d,"iss":%s}' "$((now - 60))" "$((now + 540))" "$PIPLYZER_APP_ID" | b64url)
	signing="$header.$payload"
	if ! sig=$(printf '%s' "$signing" | openssl dgst -sha256 -sign "$key" 2>/dev/null); then
		return 1
	fi
	printf '%s.%s' "$signing" "$(printf '%s' "$sig" | b64url)"
}

hook_url() {
	local jwt
	jwt=$(app_jwt) || return 1
	curl -sS \
		-H "Authorization: Bearer $jwt" \
		-H "Accept: application/vnd.github+json" \
		-H "X-GitHub-Api-Version: 2022-11-28" \
		"$api/app/hook/config" |
		sed -n 's/.*"url"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p'
}

preflight_hook() {
	local current
	current=$(hook_url) || {
		echo "piplyzer: could not read the App webhook; check the private key" >&2
		return 1
	}
	case "$current" in
	"" | *".trycloudflare.com"* | "https://example.com/piplyzer-webhook")
		return 0
		;;
	*)
		echo "piplyzer: refusing to replace webhook $current" >&2
		echo "piplyzer: this script only replaces Quick Tunnel URLs" >&2
		return 1
		;;
	esac
}

patch_hook() {
	local url=$1 jwt body
	jwt=$(app_jwt) || return 1
	body=$(printf '{"url":"%s","content_type":"json","secret":"%s"}' "$url/webhook" "$PIPLYZER_WEBHOOK_SECRET")
	curl -fsS -X PATCH \
		-H "Authorization: Bearer $jwt" \
		-H "Accept: application/vnd.github+json" \
		-H "X-GitHub-Api-Version: 2022-11-28" \
		-H "Content-Type: application/json" \
		-d "$body" \
		"$api/app/hook/config" >/dev/null
}

patch_with_retry() {
	local i
	for i in 1 2 3; do
		if patch_hook "$tunnel_url"; then
			return 0
		fi
		sleep 2
	done
	return 1
}

preflight_hook

serve_log=$(mktemp "${TMPDIR:-/tmp}/piplyzer-serve.XXXXXX.log")
serve_pid=""
echo "piplyzer: starting the check server"
PIPLYZER_PRIVATE_KEY_PATH="$key" "$binary" serve --addr "127.0.0.1:${port}" >"$serve_log" 2>&1 &
serve_pid=$!

stop_server() {
	if [ -n "${serve_pid:-}" ]; then
		kill "$serve_pid" 2>/dev/null || true
		wait "$serve_pid" 2>/dev/null || true
		serve_pid=""
	fi
}

healthy=0
for _ in {1..50}; do
	if curl -fsS "http://127.0.0.1:${port}/healthz" >/dev/null 2>&1; then
		healthy=1
		break
	fi
	if ! kill -0 "$serve_pid" 2>/dev/null; then
		break
	fi
	sleep 0.2
done
if [ "$healthy" != 1 ]; then
	echo "piplyzer: the check server did not become healthy" >&2
	cat "$serve_log" >&2 || true
	exit 1
fi

cf_pid=""
cf_log=$(mktemp "${TMPDIR:-/tmp}/piplyzer-cloudflared.XXXXXX.log")
tunnel_url=""
stopping=0
cleaned=0

stop_tunnel() {
	if [ -n "${cf_pid:-}" ]; then
		kill "$cf_pid" 2>/dev/null || true
		wait "$cf_pid" 2>/dev/null || true
		cf_pid=""
	fi
	tunnel_url=""
}

cleanup() {
	[ "$cleaned" = 1 ] && return
	cleaned=1
	trap - INT TERM EXIT
	stopping=1
	stop_tunnel
	stop_server
	rm -f "$cf_log" "$serve_log"
}
trap cleanup INT TERM EXIT

start_tunnel() {
	: >"$cf_log"
	cloudflared tunnel --url "http://127.0.0.1:${port}" --no-autoupdate >"$cf_log" 2>&1 &
	cf_pid=$!
	for _ in {1..120}; do
		if ! kill -0 "$cf_pid" 2>/dev/null; then
			echo "piplyzer: cloudflared exited" >&2
			tail -n 20 "$cf_log" >&2 || true
			cf_pid=""
			return 1
		fi
		tunnel_url=$(sed -n 's#.*\(https://[a-z0-9-]*\.trycloudflare\.com\).*#\1#p' "$cf_log" | head -n 1)
		if [ -n "$tunnel_url" ]; then
			return 0
		fi
		sleep 0.5
	done
	echo "piplyzer: timed out waiting for a Quick Tunnel" >&2
	tail -n 20 "$cf_log" >&2 || true
	stop_tunnel
	return 1
}

wait_tunnel() {
	for _ in {1..40}; do
		if curl -fsS --max-time 5 "$tunnel_url/healthz" >/dev/null 2>&1; then
			return 0
		fi
		sleep 0.5
	done
	return 1
}

printed=0
while :; do
	if ! start_tunnel; then
		[ "$stopping" = 1 ] && break
		echo "piplyzer: retrying in 3s" >&2
		sleep 3
		continue
	fi
	if ! wait_tunnel; then
		echo "piplyzer: the tunnel is not reaching the server; retrying" >&2
		stop_tunnel
		sleep 2
		continue
	fi
	if ! patch_with_retry; then
		echo "piplyzer: could not update the webhook; retrying with a new tunnel" >&2
		stop_tunnel
		sleep 2
		continue
	fi

	if [ "$printed" = 0 ]; then
		echo "piplyzer: public URL: $tunnel_url"
		echo "piplyzer: install it: https://github.com/apps/$PIPLYZER_APP_SLUG/installations/new"
		echo "piplyzer: add a branch ruleset requiring the \"piplyzer\" check, then open a pull request"
		printed=1
	else
		echo "piplyzer: tunnel restarted: $tunnel_url"
	fi

	wait "$cf_pid" || true
	cf_pid=""
	[ "$stopping" = 1 ] && break
	echo "piplyzer: tunnel closed; reconnecting" >&2
	sleep 1
done
