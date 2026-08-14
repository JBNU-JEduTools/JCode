#!/usr/bin/env bash
set -euo pipefail

target=${1:?target must be dev or prod}
case "$target" in
  dev)
    controller_namespace=dev
    workspace_service_account=jcode-workspace-v2
    legacy_subject_namespace=dev
    legacy_subject_name=jcode-generator-dev
    ;;
  prod|production)
    target=prod
    controller_namespace=watcher
    workspace_service_account=jcode-workspace-v2
    legacy_subject_namespace=watcher
    legacy_subject_name=jcode-workspace
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

legacy_bindings=$(kubectl get rolebindings -A -o json | jq -r \
  --arg target "$target" \
  --arg subject_namespace "$legacy_subject_namespace" \
  --arg subject_name "$legacy_subject_name" '
    .items[] |
    select(.metadata.namespace | startswith("jcode-")) |
    select($target != "prod" or (.metadata.namespace | startswith("jcode-dev-") | not)) |
    select(any(.subjects[]?; .kind == "ServiceAccount" and .namespace == $subject_namespace and .name == $subject_name)) |
    [.metadata.namespace, .metadata.name] | @tsv
  ')

# 모든 Namespace가 안전하게 전환됐는지 먼저 확인한다. 이 단계에서는 삭제하지 않는다.
while IFS=$'\t' read -r source_namespace binding_name; do
  [[ -n "$source_namespace" ]] || continue
  migration_state=$(kubectl get namespace "$source_namespace" -o jsonpath='{.metadata.labels.jcode\.io/migration-state}')
  if [[ "$migration_state" == quarantined ]]; then
    continue
  fi
  if [[ "$target" == dev ]]; then
    if [[ "$source_namespace" =~ ^jcode-dev-[a-z0-9]+-[0-9]+$ ]]; then
      target_namespace=$source_namespace
    else
      target_namespace="jcode-dev-${source_namespace#jcode-}"
    fi
  else
    [[ "$source_namespace" != jcode-dev-* ]] || continue
    target_namespace=$source_namespace
  fi
  kubectl get rolebinding jcode-workspace-runtime-v2 -n "$target_namespace" >/dev/null
  verify_v2_access "$target_namespace"
done <<<"$legacy_bindings"

if [[ "$target" == dev ]]; then
  [[ $(kubectl get deployment jcode-generator -n dev -o jsonpath='{.spec.template.spec.serviceAccountName}') == jcode-workspace-v2 ]]
  [[ $(kubectl get deployment jcode-bootstrap -n dev -o jsonpath='{.spec.template.spec.serviceAccountName}') == jcode-bootstrap-v2 ]]
else
  [[ $(kubectl get deployment jcode-generator -n watcher -o jsonpath='{.spec.template.spec.serviceAccountName}') == jcode-workspace-v2 ]]
  [[ $(kubectl get deployment jcode-bootstrap -n watcher -o jsonpath='{.spec.template.spec.serviceAccountName}') == jcode-bootstrap-v2 ]]
fi

# 사전 검증이 모두 끝난 뒤 구형 RoleBinding을 일괄 정리한다.
while IFS=$'\t' read -r source_namespace binding_name; do
  [[ -n "$source_namespace" ]] || continue
  kubectl delete rolebinding "$binding_name" -n "$source_namespace"
  echo "removed legacy RoleBinding: $source_namespace/$binding_name"
done <<<"$legacy_bindings"

if [[ "$target" == dev ]]; then
  kubectl delete serviceaccount jcode-generator-dev -n dev --ignore-not-found
  kubectl delete clusterrolebinding \
    jcode-generator-dev-binding \
    jcode-workspace-runtime-dev \
    namespace-reader-binding-dev \
    --ignore-not-found
else
  kubectl delete serviceaccount jcode-workspace jcode-bootstrap -n watcher --ignore-not-found
  kubectl delete clusterrolebinding jcode-bootstrap jcode-workspace-namespace-reader --ignore-not-found
fi

remaining=$(kubectl get rolebindings -A -o json | jq \
  --arg target "$target" \
  --arg subject_namespace "$legacy_subject_namespace" \
  --arg subject_name "$legacy_subject_name" '
    [.items[] |
      select($target != "prod" or (.metadata.namespace | startswith("jcode-dev-") | not)) |
      select(any(.subjects[]?; .kind == "ServiceAccount" and .namespace == $subject_namespace and .name == $subject_name))
    ] | length
  ')
[[ "$remaining" -eq 0 ]] || { echo "legacy RoleBindings remain: $remaining" >&2; exit 1; }
