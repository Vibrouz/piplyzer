#!/usr/bin/env bash
# Run the ppe GitHub App locally: create it on first run, start the container,
# open a Cloudflare Quick Tunnel, point the App webhook at that tunnel, and
# keep the two processes together. The tunnel URL changes whenever this script
# restarts, so the webhook is updated again each time.
set -euo pipefail

repo_root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
config_dir=${PPE_CONFIG_DIR:-"$repo_root/.ppe"}
# Docker treats a relative bind-mount source as a named volume, so resolve the
# path before it reaches -v. PPE_CONFIG_DIR=.ppe is the obvious thing to type.
case "$config_dir" in
/*) ;;
*) config_dir="$PWD/$config_dir" ;;
esac
image=ppe:local
container=ppe-local
# Overridable so the runner can run beside another service on this machine.
port=${PPE_PORT:-8080}
setup_port=8081
api=https://api.github.com

for cmd in docker cloudflared openssl curl; do
	if ! command -v "$cmd" >/dev/null 2>&1; then
		echo "ppe: $cmd is required" >&2
		exit 1
	fi
done

# Rebuild quietly. An image from yesterday would run yesterday's binary, and a
# cached rebuild costs a few seconds.
docker build -q -t "$image" "$repo_root" >/dev/null

if [ ! -f "$config_dir/config.env" ]; then
	mkdir -p "$config_dir"
	chmod 700 "$config_dir"
	echo "ppe: creating the GitHub App"
	docker run --rm \
		-p "127.0.0.1:${setup_port}:8081" \
		-v "$config_dir:/data" \
		--user "$(id -u):$(id -g)" \
		"$image" setup --addr 0.0.0.0:8081 --config-dir /data
	if [ ! -f "$config_dir/config.env" ]; then
		echo "ppe: setup did not write $config_dir/config.env" >&2
		exit 1
	fi
fi

set -a
# shellcheck disable=SC1091
. "$config_dir/config.env"
set +a

: "${PPE_APP_ID:?config.env is missing PPE_APP_ID}"
: "${PPE_WEBHOOK_SECRET:?config.env is missing PPE_WEBHOOK_SECRET}"
: "${PPE_APP_SLUG:?config.env is missing PPE_APP_SLUG}"

key="$config_dir/app.pem"
if [ ! -f "$key" ]; then
	echo "ppe: $key is missing" >&2
	exit 1
fi

b64url() {
	openssl base64 -A | tr '+/' '-_' | tr -d '='
}

app_jwt() {
	local now header payload signing sig
	now=$(date +%s)
	header=$(printf '%s' '{"alg":"RS256","typ":"JWT"}' | b64url)
	payload=$(printf '{"iat":%d,"exp":%d,"iss":%s}' "$((now - 60))" "$((now + 540))" "$PPE_APP_ID" | b64url)
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
		echo "ppe: could not read the App webhook; check the private key" >&2
		return 1
	}
	case "$current" in
	"" | *".trycloudflare.com"* | "https://example.com/ppe-webhook")
		return 0
		;;
	*)
		echo "ppe: refusing to replace webhook $current" >&2
		echo "ppe: this script only replaces Quick Tunnel URLs" >&2
		return 1
		;;
	esac
}

patch_hook() {
	local url=$1 jwt body
	jwt=$(app_jwt) || return 1
	body=$(printf '{"url":"%s","content_type":"json","secret":"%s"}' "$url/webhook" "$PPE_WEBHOOK_SECRET")
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

docker rm -f "$container" >/dev/null 2>&1 || true
echo "ppe: starting the check server"
docker run -d --name "$container" \
	--user "$(id -u):$(id -g)" \
	-p "127.0.0.1:${port}:8080" \
	-v "$config_dir:/data:ro" \
	-e PPE_APP_ID \
	-e PPE_WEBHOOK_SECRET \
	-e PPE_PRIVATE_KEY_PATH=/data/app.pem \
	"$image" serve --addr :8080 >/dev/null

healthy=0
for _ in {1..50}; do
	if curl -fsS "http://127.0.0.1:${port}/healthz" >/dev/null 2>&1; then
		healthy=1
		break
	fi
	if [ "$(docker inspect -f '{{.State.Running}}' "$container" 2>/dev/null || echo false)" != "true" ]; then
		break
	fi
	sleep 0.2
done
if [ "$healthy" != 1 ]; then
	echo "ppe: the check server did not become healthy" >&2
	docker logs "$container" >&2 || true
	exit 1
fi

cf_pid=""
cf_log=$(mktemp "${TMPDIR:-/tmp}/ppe-cloudflared.XXXXXX.log")
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
	docker rm -f "$container" >/dev/null 2>&1 || true
	rm -f "$cf_log"
}
trap cleanup INT TERM EXIT

start_tunnel() {
	: >"$cf_log"
	cloudflared tunnel --url "http://127.0.0.1:${port}" --no-autoupdate >"$cf_log" 2>&1 &
	cf_pid=$!
	for _ in {1..120}; do
		if ! kill -0 "$cf_pid" 2>/dev/null; then
			echo "ppe: cloudflared exited" >&2
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
	echo "ppe: timed out waiting for a Quick Tunnel" >&2
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
		echo "ppe: retrying in 3s" >&2
		sleep 3
		continue
	fi
	if ! wait_tunnel; then
		echo "ppe: the tunnel is not reaching the server; retrying" >&2
		stop_tunnel
		sleep 2
		continue
	fi
	if ! patch_with_retry; then
		echo "ppe: could not update the webhook; retrying with a new tunnel" >&2
		stop_tunnel
		sleep 2
		continue
	fi

	if [ "$printed" = 0 ]; then
		echo "ppe: public URL: $tunnel_url"
		echo "ppe: install it: https://github.com/apps/$PPE_APP_SLUG/installations/new"
		echo "ppe: add a branch ruleset requiring the \"ppe\" check, then open a pull request"
		printed=1
	else
		echo "ppe: tunnel restarted: $tunnel_url"
	fi

	wait "$cf_pid" || true
	cf_pid=""
	[ "$stopping" = 1 ] && break
	echo "ppe: tunnel closed; reconnecting" >&2
	sleep 1
done
