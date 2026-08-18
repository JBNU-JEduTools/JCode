#!/usr/bin/env bash
set -euo pipefail

target=${1:-${TARGET:-dev}}
case "$target" in
  dev)
    overlay=dev
    default_namespace=dev
    generator_configmap=jcode-generator-dev-configmap
    generator_secret=jcode-generator-dev-secret
    router_configmap=jcode-router-dev-config
    router_secret=jcode-router-dev-secret
    watcher_api_base=http://watcher-backend-service.dev.svc.cluster.local:3000
    watcher_namespace=dev
    workspace_proxy_namespace=dev
    ;;
  prod|production)
    overlay=prod
    default_namespace=watcher
    generator_configmap=jcode-generator-configmap
    generator_secret=jcode-generator-secret
    router_configmap=jcode-router-config
    router_secret=jcode-router-secret
    watcher_api_base=http://watcher-backend-service.watcher.svc.cluster.local:3000
    watcher_namespace=watcher
    workspace_proxy_namespace=watcher
    ;;
  *)
    echo "target must be dev, prod, or production: $target" >&2
    exit 2
    ;;
esac
namespace=${JCODE_NAMESPACE:-$default_namespace}
if [[ "$namespace" != "$default_namespace" ]]; then
  echo "JCODE_NAMESPACE must match the $overlay overlay namespace: $default_namespace" >&2
  exit 2
fi
workspace_proxy_url="http://jcode-router-svc.${namespace}.svc.cluster.local:3000"
harbor_registry=${HARBOR_REGISTRY:-harbor.jedutools.io}
if [[ ! "$harbor_registry" =~ ^[a-z0-9]([a-z0-9.-]*[a-z0-9])?(:[1-9][0-9]{0,4})?$ ]]; then
  echo "HARBOR_REGISTRY must be a registry host without scheme or path: $harbor_registry" >&2
  exit 2
fi
generator_digest=${GENERATOR_DIGEST:?GENERATOR_DIGEST is required}
router_digest=${ROUTER_DIGEST:?ROUTER_DIGEST is required}
code_server_digest=${CODE_SERVER_DIGEST:?CODE_SERVER_DIGEST is required}
code_server_vnc_digest=${CODE_SERVER_VNC_DIGEST:?CODE_SERVER_VNC_DIGEST is required}
workspace_init_digest=${WORKSPACE_INIT_DIGEST:?WORKSPACE_INIT_DIGEST is required}
squid_exporter_digest=${SQUID_EXPORTER_DIGEST:?SQUID_EXPORTER_DIGEST is required}
allowed_network_cidr=${ALLOWED_NETWORK_CIDR:?ALLOWED_NETWORK_CIDR is required}
workspace_dns_cidrs=${WORKSPACE_DNS_CIDRS:?WORKSPACE_DNS_CIDRS is required}
workspace_resource_profiles_json=${WORKSPACE_RESOURCE_PROFILES_JSON:?WORKSPACE_RESOURCE_PROFILES_JSON is required}

for digest in "$generator_digest" "$router_digest" "$code_server_digest" "$code_server_vnc_digest" "$workspace_init_digest" "$squid_exporter_digest"; do
  if [[ ! "$digest" =~ ^sha256:[0-9a-f]{64}$ ]]; then
    echo "invalid digest: $digest" >&2
    exit 2
  fi
done
python3 - "$allowed_network_cidr" "$workspace_dns_cidrs" "$workspace_resource_profiles_json" <<'PY'
import ipaddress
import json
import sys

try:
    ipaddress.ip_network(sys.argv[1], strict=False)
except ValueError as error:
    raise SystemExit(f"ALLOWED_NETWORK_CIDR is invalid: {error}")

dns_cidrs = [value.strip() for value in sys.argv[2].split(",") if value.strip()]
if not dns_cidrs:
    raise SystemExit("WORKSPACE_DNS_CIDRS must contain at least one CIDR")
for value in dns_cidrs:
    if "/" not in value:
        raise SystemExit(f"WORKSPACE_DNS_CIDRS contains an invalid CIDR: {value}")
    try:
        ipaddress.ip_network(value, strict=True)
    except ValueError as error:
        raise SystemExit(f"WORKSPACE_DNS_CIDRS contains an invalid CIDR ({value}): {error}")

try:
    profiles = json.loads(sys.argv[3])
except json.JSONDecodeError as error:
    raise SystemExit(f"WORKSPACE_RESOURCE_PROFILES_JSON is invalid JSON: {error}")
for name in ("STANDARD", "HIGH_MEMORY", "GPU"):
    value = profiles.get(name)
    if not isinstance(value, dict) or not isinstance(value.get("requests"), dict) or not isinstance(value.get("limits"), dict):
        raise SystemExit(f"WORKSPACE_RESOURCE_PROFILES_JSON is missing {name} requests/limits")
PY

for resource in \
  crd/externalsecrets.external-secrets.io \
  clustersecretstore/jcode-harbor-pull-secret \
  "configmap/$generator_configmap" \
  "secret/$generator_secret" \
  "configmap/$router_configmap" \
  "secret/$router_secret" \
  "secret/watcher-harbor-registry-secret" \
  "persistentvolumeclaim/jcode-vol-pvc" \
  "persistentvolumeclaim/jcode-starter-pvc" \
  "persistentvolumeclaim/jcode-archive-pvc"; do
  case "$resource" in
    crd/*|clustersecretstore/*) kubectl get "$resource" >/dev/null ;;
    *) kubectl get "$resource" -n "$namespace" >/dev/null ;;
  esac
done
kubectl get validatingadmissionpolicy/jcode-bootstrap-resources-v2 >/dev/null || {
  echo "v2 admission boundary is not installed; run deploy/install-cluster-v2.sh prepare $overlay first" >&2
  exit 2
}
if [[ "$overlay" == dev ]]; then
  kubectl get validatingadmissionpolicy/jcode-course-metadata-dev-v2 >/dev/null || {
    echo "dev metadata policy is not installed; run deploy/install-cluster-v2.sh prepare dev first" >&2
    exit 2
  }
fi

if ! kubectl api-resources --api-group=admissionregistration.k8s.io -o name | grep -q '^validatingadmissionpolicies\.'; then
  echo "cluster does not support admissionregistration.k8s.io/v1 ValidatingAdmissionPolicy" >&2
  exit 2
fi

for resource in \
  clusterrole/jcode-bootstrap-v2 \
  clusterrole/jcode-workspace-runtime-v2 \
  clusterrole/jcode-workspace-namespace-reader-v2; do
  kubectl get "$resource" >/dev/null || {
    echo "$resource is not installed; run deploy/install-cluster-v2.sh prepare $overlay first" >&2
    exit 2
  }
done

JCODE_NAMESPACE="$namespace" GENERATOR_CONFIGMAP_NAME="$generator_configmap" \
  generator/k8s/configure-workspace-storage.sh
ROUTER_NAMESPACE="$namespace" HTTP_PORT=3000 ALLOWED_NETWORK_CIDR="$allowed_network_cidr" \
  router/k8s/configure-squid.sh

render_dir=$(mktemp -d)
trap 'rm -rf "$render_dir"' EXIT
kubectl kustomize "deploy/overlays/$overlay" > "$render_dir/platform.yaml"
python3 - "$generator_digest" "$router_digest" "$squid_exporter_digest" "$harbor_registry" "$render_dir/platform.yaml" <<'PY'
import sys
from pathlib import Path

generator_digest, router_digest, squid_exporter_digest, harbor_registry, output = sys.argv[1:]
path = Path(output)
content = path.read_text(encoding="utf-8")
content = content.replace(
    "harbor.jedutools.io/jdevops/jcode-generator:REPLACE_WITH_COMMIT_SHA",
    f"{harbor_registry}/jdevops/jcode-generator@{generator_digest}",
)
content = content.replace(
    "harbor.jedutools.io/jdevops/jcode-router:REPLACE_WITH_COMMIT_SHA",
    f"{harbor_registry}/jdevops/jcode-router@{router_digest}",
)
content = content.replace(
    "harbor.jedutools.io/jdevops/squid-exporter:REPLACE_WITH_COMMIT_SHA",
    f"{harbor_registry}/jdevops/squid-exporter@{squid_exporter_digest}",
)
if "REPLACE_WITH_COMMIT_SHA" in content:
    raise SystemExit("rendered manifest contains an unresolved image placeholder")
path.write_text(content, encoding="utf-8")
PY

config_patch="$render_dir/generator-images.json"
jq -n \
  --arg harbor_registry "$harbor_registry" \
  --arg code_server_image "$harbor_registry/jdevops/code-server@$code_server_digest" \
  --arg code_server_vnc_image "$harbor_registry/jdevops/code-server-vnc@$code_server_vnc_digest" \
  --arg workspace_init_image "$harbor_registry/jdevops/workspace-init@$workspace_init_digest" \
  --arg watcher_api_base "$watcher_api_base" \
  --arg workspace_dns_cidrs "$workspace_dns_cidrs" \
  --arg workspace_resource_profiles_json "$workspace_resource_profiles_json" \
  --arg workspace_proxy_url "$workspace_proxy_url" \
  --arg watcher_namespace "$watcher_namespace" \
  --arg workspace_proxy_namespace "$workspace_proxy_namespace" \
  '{data:{HARBOR_REGISTRY:$harbor_registry,CODE_SERVER_IMAGE:$code_server_image,CODE_SERVER_VNC_IMAGE:$code_server_vnc_image,WORKSPACE_INIT_IMAGE:$workspace_init_image,WATCHER_API_BASE:$watcher_api_base,WORKSPACE_DNS_CIDRS:$workspace_dns_cidrs,WORKSPACE_RESOURCE_PROFILES_JSON:$workspace_resource_profiles_json,WORKSPACE_PROXY_URL:$workspace_proxy_url,WATCHER_NAMESPACE:$watcher_namespace,WORKSPACE_PROXY_NAMESPACE:$workspace_proxy_namespace,WORKSPACE_PROXY_POD_LABEL:"jcode-router",WORKSPACE_PROXY_PORT:"3000"}}' \
  > "$config_patch"
kubectl patch configmap "$generator_configmap" -n "$namespace" --type=merge --patch-file "$config_patch"
kubectl apply -f "$render_dir/platform.yaml"

kubectl rollout restart deployment/jcode-generator deployment/jcode-bootstrap deployment/jcode-router -n "$namespace"
kubectl rollout status deployment/jcode-generator -n "$namespace" --timeout=5m
kubectl rollout status deployment/jcode-bootstrap -n "$namespace" --timeout=5m
kubectl rollout status deployment/jcode-router -n "$namespace" --timeout=5m
kubectl rollout status deployment/squid-exporter -n "$namespace" --timeout=5m

python3 deploy/reconcile_workspace_dns.py "$overlay" \
  --namespace "$namespace" \
  --configmap "$generator_configmap"
