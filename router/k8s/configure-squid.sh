#!/usr/bin/env bash
set -euo pipefail

namespace=${ROUTER_NAMESPACE:-watcher}
port=${HTTP_PORT:-3000}
allowed_cidr=${ALLOWED_NETWORK_CIDR:?ALLOWED_NETWORK_CIDR is required}

if [[ ! "$port" =~ ^[0-9]+$ ]] || (( port < 1 || port > 65535 )); then
  echo "HTTP_PORT must be between 1 and 65535" >&2
  exit 2
fi
python3 - "$allowed_cidr" <<'PY'
import ipaddress
import sys

try:
    ipaddress.ip_network(sys.argv[1], strict=False)
except ValueError as error:
    raise SystemExit(f"ALLOWED_NETWORK_CIDR is invalid: {error}")
PY

config_file=$(mktemp)
trap 'rm -f "$config_file"' EXIT
{
  echo "http_port ${port}"
  echo "acl workspace_network src ${allowed_cidr}"
  echo "acl cache_manager urlpath_regex -i ^/squid-internal-mgr/"
  echo "acl blocked_destination dst 10.0.0.0/8 100.64.0.0/10 127.0.0.0/8 169.254.0.0/16 172.16.0.0/12 192.168.0.0/16 ::1/128 fc00::/7 fe80::/10"
  echo "http_access allow cache_manager workspace_network"
  echo "http_access deny cache_manager"
  echo "http_access deny blocked_destination"
  echo "http_access allow workspace_network"
  echo "http_access deny all"
  echo "cache deny all"
  echo "cache_dir null /dev/null"
  echo "cache_mem 0 MB"
} > "$config_file"

for required_line in \
  "acl workspace_network src ${allowed_cidr}" \
  "acl cache_manager urlpath_regex -i ^/squid-internal-mgr/" \
  "http_access allow cache_manager workspace_network" \
  "http_access deny cache_manager" \
  "http_access allow workspace_network" \
  "http_access deny all"; do
  grep -Fxq "$required_line" "$config_file" || {
    echo "generated squid.conf is missing: $required_line" >&2
    exit 2
  }
done

kubectl create configmap squid-config \
  --namespace "$namespace" \
  --from-file="squid.conf=${config_file}" \
  --dry-run=client -o yaml | kubectl apply -f -

applied_config=$(kubectl get configmap squid-config --namespace "$namespace" -o jsonpath='{.data.squid\.conf}')
for required_line in \
  "acl workspace_network src ${allowed_cidr}" \
  "acl cache_manager urlpath_regex -i ^/squid-internal-mgr/" \
  "http_access allow cache_manager workspace_network" \
  "http_access deny cache_manager" \
  "http_access allow workspace_network" \
  "http_access deny all"; do
  grep -Fxq "$required_line" <<<"$applied_config" || {
    echo "applied squid.conf is missing: $required_line" >&2
    exit 2
  }
done
