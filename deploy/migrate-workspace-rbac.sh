#!/usr/bin/env bash
set -euo pipefail

for command in kubectl jq curl python3 base64; do
  command -v "$command" >/dev/null || { echo "$command is required" >&2; exit 2; }
done

target=${1:?target must be dev or prod}
legacy_plan=${LEGACY_NAMESPACE_PLAN:-deploy/legacy-namespace-plan.json}
jq -e '.schema == 1 and (.environments.dev | type == "object") and (.environments.prod | type == "object")' "$legacy_plan" >/dev/null
# shellcheck source=deploy/legacy-plan.sh
source "$(dirname "$0")/legacy-plan.sh"
case "$target" in
  dev)
    controller_namespace=dev
    workspace_service_account=jcode-workspace-v2
    bootstrap_url=${BOOTSTRAP_URL:?BOOTSTRAP_URL is required for dev migration}
    source_role_namespace=dev
    source_role_service_account=jcode-generator-dev
    # shellcheck source=deploy/generator-token.sh
    source "$(dirname "$0")/generator-token.sh"
    load_generator_service_secret dev jcode-generator-dev-secret
    ;;
  prod|production)
    target=prod
    controller_namespace=watcher
    workspace_service_account=jcode-workspace-v2
    ;;
  *)
    echo "target must be dev or prod: $target" >&2
    exit 2
    ;;
esac

verify_v2_access() {
  local namespace=$1
  local user="system:serviceaccount:${controller_namespace}:${workspace_service_account}"
  [[ $(kubectl auth can-i create deployments.apps -n "$namespace" --as="$user") == yes ]]
  [[ $(kubectl auth can-i delete deployments.apps -n "$namespace" --as="$user") == yes ]]
}

quarantine_legacy_namespace() {
  local namespace=$1 reason=$2
  kubectl label namespace "$namespace" jcode.io/migration-state=quarantined --overwrite >/dev/null
  kubectl annotate namespace "$namespace" "jcode.io/migration-reason=$reason" --overwrite >/dev/null
  echo "quarantined metadata-less $target namespace without deleting workloads: $namespace"
}

apply_v2_binding() {
  local namespace=$1
  kubectl apply -f - >/dev/null <<EOF
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: jcode-workspace-runtime-v2
  namespace: ${namespace}
  labels:
    app.kubernetes.io/managed-by: jcode-rbac-migration
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: ClusterRole
  name: jcode-workspace-runtime-v2
subjects:
  - kind: ServiceAccount
    name: ${workspace_service_account}
    namespace: ${controller_namespace}
EOF
  verify_v2_access "$namespace"
}

if [[ "$target" == prod ]]; then
  legacy_namespaces=$(kubectl get rolebindings -A -o json | jq -r '
    .items[] |
    select(.metadata.namespace | startswith("jcode-") and (startswith("jcode-dev-") | not)) |
    select(any(.subjects[]?; .kind == "ServiceAccount" and .namespace == "watcher" and .name == "jcode-workspace")) |
    .metadata.namespace
  ' | sort -u)
  while IFS= read -r namespace; do
    [[ -n "$namespace" ]] || continue
    if ! kubectl get configmap jcode-course-metadata -n "$namespace" >/dev/null 2>&1; then
      load_legacy_plan_entry "$legacy_plan" "$target" "$namespace"
      [[ "$action" == quarantine ]] || {
        echo "production metadata-less namespace only supports quarantine: $namespace" >&2
        exit 2
      }
      quarantine_legacy_namespace "$namespace" "$reason"
      continue
    fi
    bindings=$(kubectl get rolebindings -n "$namespace" -o json)
    prod_legacy=$(jq '[.items[].subjects[]? | select(.kind == "ServiceAccount" and .namespace == "watcher" and .name == "jcode-workspace")] | length' <<<"$bindings")
    dev_legacy=$(jq '[.items[].subjects[]? | select(.kind == "ServiceAccount" and .namespace == "dev" and .name == "jcode-generator-dev")] | length' <<<"$bindings")
    recorded_environment=$(kubectl get namespace "$namespace" -o jsonpath='{.metadata.labels.jcode\.io/environment}')
    if [[ "$prod_legacy" -gt 0 && "$dev_legacy" -gt 0 ]]; then
      echo "mixed dev/prod legacy ownership: $namespace" >&2
      exit 2
    fi
    if [[ "$dev_legacy" -gt 0 || "$recorded_environment" == dev ]]; then
      continue
    fi
    if [[ "$prod_legacy" -eq 0 && "$recorded_environment" != prod ]]; then
      echo "cannot classify production namespace ownership: $namespace" >&2
      exit 2
    fi
    apply_v2_binding "$namespace"
    echo "prepared production RBAC: $namespace"
  done <<<"$legacy_namespaces"
  exit 0
fi

legacy_namespaces=$(kubectl get rolebindings -A -o json | jq -r \
  --arg subject_namespace "$source_role_namespace" \
  --arg subject_name "$source_role_service_account" '
    .items[] |
    select(.metadata.namespace | startswith("jcode-")) |
    select(any(.subjects[]?; .kind == "ServiceAccount" and .namespace == $subject_namespace and .name == $subject_name)) |
    .metadata.namespace
  ' | sort -u)

while IFS= read -r source_namespace; do
  [[ -n "$source_namespace" ]] || continue
  session_policy=
  if [[ "$source_namespace" =~ ^jcode-dev-[a-z0-9]+-[0-9]+$ ]]; then
    target_namespace=$source_namespace
  else
    target_namespace="jcode-dev-${source_namespace#jcode-}"
  fi

  if kubectl get configmap jcode-course-metadata -n "$source_namespace" >/dev/null 2>&1; then
    course_id=$(kubectl get configmap jcode-course-metadata -n "$source_namespace" -o jsonpath='{.data.course-id}')
    use_vnc=false
    if kubectl get configmap watcher-hook-config -n "$source_namespace" >/dev/null 2>&1; then
      use_vnc=true
    fi
  else
    load_legacy_plan_entry "$legacy_plan" "$target" "$source_namespace"
    if [[ "$action" == quarantine ]]; then
      quarantine_legacy_namespace "$source_namespace" "$reason"
      continue
    fi
    [[ "$plan_target_namespace" == "$target_namespace" ]] || {
      echo "migration target mismatch for $source_namespace: $plan_target_namespace != $target_namespace" >&2
      exit 2
    }
    [[ "$session_policy" == recreate ]] || {
      echo "unsupported session policy for $source_namespace: $session_policy" >&2
      exit 2
    }
  fi
  [[ "$course_id" =~ ^[1-9][0-9]*$ ]]
  token=$(create_generator_token namespace:write)
  body=$(jq -n \
    --arg namespace "$source_namespace" \
    --argjson course_id "$course_id" \
    --argjson use_vnc "$use_vnc" \
    '{namespace:$namespace,course_id:$course_id,use_vnc:$use_vnc}')
  response=$(curl --fail-with-body --silent --show-error \
    -H "Authorization: Bearer $token" \
    -H 'Content-Type: application/json' \
    --data "$body" \
    "$bootstrap_url/api/namespace")
  [[ $(jq -r '.namespace' <<<"$response") == "$target_namespace" ]]
  verify_v2_access "$target_namespace"
  if [[ ${session_policy:-} == recreate ]]; then
    # 기존 세션은 workload를 복사하지 않는다. NFS 데이터는 유지하고 다음 접속 시 새 Namespace에서 재생성한다.
    kubectl delete deployments.apps,services --all -n "$source_namespace" --ignore-not-found
    if [[ $(kubectl get pods -n "$source_namespace" -o json | jq '.items | length') -gt 0 ]]; then
      kubectl wait --for=delete pods --all -n "$source_namespace" --timeout=5m
    fi
    kubectl label namespace "$source_namespace" jcode.io/migration-state=superseded --overwrite >/dev/null
  fi
  echo "prepared dev namespace and RBAC: $source_namespace -> $target_namespace"
done <<<"$legacy_namespaces"
