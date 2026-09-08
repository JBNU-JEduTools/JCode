#!/usr/bin/env bash
set -euo pipefail

target=${1:?target must be dev or prod}
case "$target" in
  dev)
    controller_namespace=dev
    workspace_service_account=jcode-workspace-v2
    legacy_subject_namespace=dev
    legacy_subject_names='["jcode-generator-dev"]'
    legacy_cluster_subject_names='["jcode-generator-dev"]'
    legacy_service_accounts=(jcode-generator-dev)
    ;;
  prod|production)
    target=prod
    controller_namespace=watcher
    workspace_service_account=jcode-workspace-v2
    legacy_subject_namespace=watcher
    legacy_subject_names='["jcode-generator","jcode-workspace"]'
    legacy_cluster_subject_names='["jcode-generator","jcode-workspace","jcode-bootstrap"]'
    legacy_service_accounts=(jcode-generator jcode-workspace jcode-bootstrap)
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

rolebindings=$(kubectl get rolebindings -A -o json)
unsafe_legacy_bindings=$(jq -r \
  --arg target "$target" \
  --arg subject_namespace "$legacy_subject_namespace" \
  --argjson subject_names "$legacy_subject_names" '
    .items[] |
    select(.metadata.namespace | startswith("jcode-")) |
    select($target != "prod" or (.metadata.namespace | startswith("jcode-dev-") | not)) |
    select(any(.subjects[]?;
      .kind == "ServiceAccount" and
      .namespace == $subject_namespace and
      (.name as $name | $subject_names | index($name)))) |
    select(all(.subjects[]?;
      .kind == "ServiceAccount" and
      .namespace == $subject_namespace and
      (.name as $name | $subject_names | index($name))) | not) |
    [.metadata.namespace, .metadata.name] | @tsv
  ' <<<"$rolebindings")
if [[ -n "$unsafe_legacy_bindings" ]]; then
  echo "refusing to delete RoleBindings with mixed legacy and unrelated subjects:" >&2
  echo "$unsafe_legacy_bindings" >&2
  exit 1
fi

legacy_bindings=$(jq -r \
  --arg target "$target" \
  --arg subject_namespace "$legacy_subject_namespace" \
  --argjson subject_names "$legacy_subject_names" '
    .items[] |
    select(.metadata.namespace | startswith("jcode-")) |
    select($target != "prod" or (.metadata.namespace | startswith("jcode-dev-") | not)) |
    select(any(.subjects[]?;
      .kind == "ServiceAccount" and
      .namespace == $subject_namespace and
      (.name as $name | $subject_names | index($name)))) |
    [.metadata.namespace, .metadata.name] | @tsv
  ' <<<"$rolebindings")

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

clusterrolebindings=$(kubectl get clusterrolebindings -o json)
unsafe_legacy_cluster_bindings=$(jq -r \
  --arg subject_namespace "$legacy_subject_namespace" \
  --argjson subject_names "$legacy_cluster_subject_names" '
    .items[] |
    select(any(.subjects[]?;
      .kind == "ServiceAccount" and
      .namespace == $subject_namespace and
      (.name as $name | $subject_names | index($name)))) |
    select(all(.subjects[]?;
      .kind == "ServiceAccount" and
      .namespace == $subject_namespace and
      (.name as $name | $subject_names | index($name))) | not) |
    .metadata.name
  ' <<<"$clusterrolebindings")
if [[ -n "$unsafe_legacy_cluster_bindings" ]]; then
  echo "refusing to delete ClusterRoleBindings with mixed legacy and unrelated subjects:" >&2
  echo "$unsafe_legacy_cluster_bindings" >&2
  exit 1
fi

legacy_cluster_bindings=$(jq -r \
  --arg subject_namespace "$legacy_subject_namespace" \
  --argjson subject_names "$legacy_cluster_subject_names" '
    .items[] |
    select(any(.subjects[]?;
      .kind == "ServiceAccount" and
      .namespace == $subject_namespace and
      (.name as $name | $subject_names | index($name)))) |
    .metadata.name
  ' <<<"$clusterrolebindings")

# 사전 검증이 모두 끝난 뒤 구형 RoleBinding을 일괄 정리한다.
while IFS=$'\t' read -r source_namespace binding_name; do
  [[ -n "$source_namespace" ]] || continue
  kubectl delete rolebinding "$binding_name" -n "$source_namespace" --ignore-not-found
  echo "removed legacy RoleBinding: $source_namespace/$binding_name"
done <<<"$legacy_bindings"

while IFS= read -r binding_name; do
  [[ -n "$binding_name" ]] || continue
  kubectl delete clusterrolebinding "$binding_name" --ignore-not-found
  echo "removed legacy ClusterRoleBinding: $binding_name"
done <<<"$legacy_cluster_bindings"

kubectl delete serviceaccount "${legacy_service_accounts[@]}" \
  -n "$controller_namespace" --ignore-not-found

remaining=$(kubectl get rolebindings -A -o json | jq \
  --arg target "$target" \
  --arg subject_namespace "$legacy_subject_namespace" \
  --argjson subject_names "$legacy_subject_names" '
    [.items[] |
      select(.metadata.namespace | startswith("jcode-")) |
      select($target != "prod" or (.metadata.namespace | startswith("jcode-dev-") | not)) |
      select(any(.subjects[]?;
        .kind == "ServiceAccount" and
        .namespace == $subject_namespace and
        (.name as $name | $subject_names | index($name))))
    ] | length
  ')
[[ "$remaining" -eq 0 ]] || { echo "legacy RoleBindings remain: $remaining" >&2; exit 1; }

remaining_cluster_bindings=$(kubectl get clusterrolebindings -o json | jq \
  --arg subject_namespace "$legacy_subject_namespace" \
  --argjson subject_names "$legacy_cluster_subject_names" '
    [.items[] |
      select(any(.subjects[]?;
        .kind == "ServiceAccount" and
        .namespace == $subject_namespace and
        (.name as $name | $subject_names | index($name))))
    ] | length
  ')
[[ "$remaining_cluster_bindings" -eq 0 ]] || {
  echo "legacy ClusterRoleBindings remain: $remaining_cluster_bindings" >&2
  exit 1
}
