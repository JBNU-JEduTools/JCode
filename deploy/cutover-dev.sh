#!/usr/bin/env bash
set -euo pipefail

namespace=${JCODE_NAMESPACE:-dev}
backend_namespace=${BACKEND_NAMESPACE:-dev}
backend_configmap=${BACKEND_CONFIGMAP:-}
backend_deployment=${BACKEND_DEPLOYMENT:?BACKEND_DEPLOYMENT is required}
backup_dir=${CUTOVER_BACKUP_DIR:-cutover-backup}
backend_config_script=${BACKEND_CONFIG_SCRIPT:-deploy/update-backend-generator-config.sh}

if [[ "$namespace" != dev || "$backend_namespace" != dev ]]; then
  echo "dev cutover only supports the dev namespace" >&2
  exit 2
fi
if [[ ${CONFIRM_DEV_CUTOVER:-} != dev ]]; then
  echo "set CONFIRM_DEV_CUTOVER=dev to run the traffic cutover" >&2
  exit 2
fi
for command in kubectl jq curl; do
  command -v "$command" >/dev/null || { echo "$command is required" >&2; exit 2; }
done

if [[ -z "$backend_configmap" ]]; then
  backend_configmap=$(kubectl get deployment "$backend_deployment" -n "$backend_namespace" -o json | \
    jq -er '[.spec.template.spec.containers[].envFrom[]?.configMapRef.name] | first')
fi

mkdir -p "$backup_dir"
kubectl get configmap "$backend_configmap" -n "$backend_namespace" -o yaml > "$backup_dir/backend-configmap.yaml"
kubectl get ingress -n "$namespace" -o yaml > "$backup_dir/ingresses.yaml"
kubectl get rolebindings -A -o yaml > "$backup_dir/rolebindings.yaml"
kubectl get serviceaccount jcode-generator-dev -n dev -o yaml > "$backup_dir/serviceaccount-jcode-generator-dev.yaml" 2>/dev/null || true
for resource in \
  deployment/jcode-generator-dev \
  deployment/jcode-router-dev \
  service/jcode-generator-dev-svc \
  service/jcode-router-dev-svc; do
  kubectl get "$resource" -n "$namespace" -o yaml > "$backup_dir/${resource//\//-}.yaml" 2>/dev/null || true
done
for binding in jcode-generator-dev-binding jcode-workspace-runtime-dev namespace-reader-binding-dev; do
  kubectl get clusterrolebinding "$binding" -o yaml > "$backup_dir/clusterrolebinding-$binding.yaml" 2>/dev/null || true
done

for deployment in jcode-bootstrap jcode-generator jcode-router; do
  kubectl rollout status "deployment/$deployment" -n "$namespace" --timeout=5m
done

bootstrap_user=system:serviceaccount:dev:jcode-bootstrap-v2
[[ $(kubectl auth can-i bind clusterrole/jcode-workspace-runtime-v2 --as="$bootstrap_user") == yes ]]
[[ $(kubectl auth can-i bind clusterrole/cluster-admin --as="$bootstrap_user") == no ]]
kubectl create --as="$bootstrap_user" --dry-run=server -f - >/dev/null <<'EOF'
apiVersion: v1
kind: Namespace
metadata:
  name: jcode-dev-cutover-1
  labels:
    jcode.io/course-id: "1"
    jcode.io/environment: dev
  annotations:
    jcode.io/course-id: "1"
    jcode.io/environment: dev
EOF
if kubectl create --as="$bootstrap_user" --dry-run=server -f - >/dev/null 2>&1 <<'EOF'
apiVersion: v1
kind: Namespace
metadata:
  name: jcode-cutover-1
  labels:
    jcode.io/course-id: "1"
    jcode.io/environment: dev
  annotations:
    jcode.io/course-id: "1"
    jcode.io/environment: dev
EOF
then
  echo "dev Bootstrap unexpectedly passed the production namespace boundary" >&2
  exit 1
fi

port_forward() {
  local service=$1 local_port=$2 remote_port=$3
  kubectl port-forward -n "$namespace" "service/$service" "$local_port:$remote_port" \
    >"$backup_dir/port-forward-$service.log" 2>&1 &
  echo $!
}

bootstrap_pid=$(port_forward jcode-bootstrap-svc 15000 5000)
generator_pid=$(port_forward jcode-generator-svc 15001 5000)
router_pid=$(port_forward jcode-router-svc 13001 3001)
cleanup() {
  kill "$bootstrap_pid" "$generator_pid" "$router_pid" 2>/dev/null || true
}
trap cleanup EXIT

for endpoint in http://127.0.0.1:15000/health/ready http://127.0.0.1:15001/health/ready; do
  for _ in $(seq 1 30); do
    curl --fail --silent --output /dev/null "$endpoint" && break
    sleep 1
  done
  curl --fail --silent --output /dev/null "$endpoint"
done
for _ in $(seq 1 30); do
  if (echo >/dev/tcp/127.0.0.1/13001) 2>/dev/null; then break; fi
  sleep 1
done
(echo >/dev/tcp/127.0.0.1/13001) 2>/dev/null

BOOTSTRAP_URL=http://127.0.0.1:15000 deploy/migrate-workspace-rbac.sh dev
BOOTSTRAP_URL=http://127.0.0.1:15000 \
  WORKSPACE_URL=http://127.0.0.1:15001 \
  deploy/smoke-workspace-lifecycle.sh dev

BACKEND_NAMESPACE="$backend_namespace" \
  BACKEND_CONFIGMAP="$backend_configmap" \
  GENERATOR_BOOTSTRAP_URL=http://jcode-bootstrap-svc:5000 \
  GENERATOR_WORKSPACE_URL=http://jcode-generator-svc:5000 \
  "$backend_config_script"
kubectl rollout restart "deployment/$backend_deployment" -n "$backend_namespace"
kubectl rollout status "deployment/$backend_deployment" -n "$backend_namespace" --timeout=5m

ingresses=$(kubectl get ingress -n "$namespace" -o json)
legacy_router_refs=$(jq '[.items[].spec.rules[]?.http.paths[]? | select(.backend.service.name == "jcode-router-dev-svc")] | length' <<<"$ingresses")
new_router_refs=$(jq '[.items[].spec.rules[]?.http.paths[]? | select(.backend.service.name == "jcode-router-svc")] | length' <<<"$ingresses")
if kubectl get service jcode-router-dev-svc -n "$namespace" >/dev/null 2>&1 && \
   [[ "$legacy_router_refs" -eq 0 && "$new_router_refs" -eq 0 ]]; then
  echo "no dev Ingress points to the legacy or v2 Router service" >&2
  exit 1
fi
if [[ "$legacy_router_refs" -gt 0 ]]; then
  while IFS=$'\t' read -r ingress_name rule_index path_index; do
    patch=$(jq -n \
      --arg path "/spec/rules/$rule_index/http/paths/$path_index/backend/service/name" \
      '[{op:"replace",path:$path,value:"jcode-router-svc"}]')
    kubectl patch ingress "$ingress_name" -n "$namespace" --type=json --patch "$patch"
  done < <(jq -r '
    .items[] |
    .metadata.name as $name |
    .spec.rules | to_entries[] |
    .key as $rule |
    .value.http.paths | to_entries[] |
    select(.value.backend.service.name == "jcode-router-dev-svc") |
    [$name, $rule, .key] | @tsv
  ' <<<"$ingresses")
fi
remaining_refs=$(kubectl get ingress -n "$namespace" -o json | jq '[.items[].spec.rules[]?.http.paths[]? | select(.backend.service.name == "jcode-router-dev-svc")] | length')
[[ "$remaining_refs" -eq 0 ]] || { echo "legacy Router ingress reference remains" >&2; exit 1; }
active_refs=$(kubectl get ingress -n "$namespace" -o json | jq '[.items[].spec.rules[]?.http.paths[]? | select(.backend.service.name == "jcode-router-svc")] | length')
[[ "$active_refs" -gt 0 ]] || { echo "no Ingress points to the v2 Router service" >&2; exit 1; }

kubectl delete deployment jcode-generator-dev jcode-router-dev -n "$namespace" --ignore-not-found
kubectl delete service jcode-generator-dev-svc jcode-router-dev-svc -n "$namespace" --ignore-not-found
deploy/finalize-workspace-rbac.sh dev

echo "dev traffic cutover completed; backup: $backup_dir"
