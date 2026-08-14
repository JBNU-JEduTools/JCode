#!/usr/bin/env bash
set -euo pipefail

metadata_name=jcode-course-metadata
environment=${1:?environment must be dev or prod}
case "$environment" in
  dev) namespace_prefix=jcode-dev- ;;
  prod) namespace_prefix=jcode- ;;
  *) echo "environment must be dev or prod: $environment" >&2; exit 2 ;;
esac

while IFS= read -r namespace; do
  [[ "$namespace" == "$namespace_prefix"* ]] || continue
  if [[ "$environment" == prod && "$namespace" == jcode-dev-* ]]; then
    continue
  fi

  if ! kubectl get configmap "$metadata_name" -n "$namespace" >/dev/null 2>&1; then
    echo "skip $namespace: $metadata_name 없음" >&2
    continue
  fi

  if [[ "$environment" == prod ]]; then
    bindings=$(kubectl get rolebindings -n "$namespace" -o json)
    prod_legacy=$(jq '[.items[].subjects[]? | select(.kind == "ServiceAccount" and .namespace == "watcher" and .name == "jcode-workspace")] | length' <<<"$bindings")
    dev_legacy=$(jq '[.items[].subjects[]? | select(.kind == "ServiceAccount" and .namespace == "dev" and .name == "jcode-generator-dev")] | length' <<<"$bindings")
    prod_v2=$(jq '[.items[].subjects[]? | select(.kind == "ServiceAccount" and .namespace == "watcher" and .name == "jcode-workspace-v2")] | length' <<<"$bindings")
    recorded_environment=$(kubectl get namespace "$namespace" -o jsonpath='{.metadata.labels.jcode\.io/environment}')
    if [[ "$prod_legacy" -gt 0 && "$dev_legacy" -gt 0 ]]; then
      echo "mixed dev/prod legacy ownership: $namespace" >&2
      exit 2
    fi
    if [[ "$dev_legacy" -gt 0 || "$recorded_environment" == dev ]]; then
      echo "skip legacy dev namespace during production migration: $namespace" >&2
      continue
    fi
    if [[ "$prod_legacy" -eq 0 && "$prod_v2" -eq 0 && "$recorded_environment" != prod ]]; then
      echo "cannot classify production namespace ownership: $namespace" >&2
      exit 2
    fi
  fi

  course_id=$(kubectl get configmap "$metadata_name" -n "$namespace" -o jsonpath='{.data.course-id}')
  metadata_namespace=$(kubectl get configmap "$metadata_name" -n "$namespace" -o jsonpath='{.data.namespace}')
  metadata_environment=$(kubectl get configmap "$metadata_name" -n "$namespace" -o jsonpath='{.data.environment}')
  if [[ ! "$course_id" =~ ^[1-9][0-9]*$ || "$metadata_namespace" != "$namespace" ]]; then
    echo "invalid course metadata: $namespace" >&2
    exit 2
  fi
  if [[ -n "$metadata_environment" && "$metadata_environment" != "$environment" ]]; then
    echo "metadata environment mismatch: $namespace" >&2
    exit 2
  fi

  current_label=$(kubectl get namespace "$namespace" -o jsonpath='{.metadata.labels.jcode\.io/course-id}')
  current_annotation=$(kubectl get namespace "$namespace" -o jsonpath='{.metadata.annotations.jcode\.io/course-id}')
  current_environment_label=$(kubectl get namespace "$namespace" -o jsonpath='{.metadata.labels.jcode\.io/environment}')
  current_environment_annotation=$(kubectl get namespace "$namespace" -o jsonpath='{.metadata.annotations.jcode\.io/environment}')
  if [[ -n "$current_label" && "$current_label" != "$course_id" ]] || \
     [[ -n "$current_annotation" && "$current_annotation" != "$course_id" ]]; then
    echo "namespace course-id mismatch: $namespace" >&2
    exit 2
  fi
  if [[ -n "$current_environment_label" && "$current_environment_label" != "$environment" ]] || \
     [[ -n "$current_environment_annotation" && "$current_environment_annotation" != "$environment" ]]; then
    echo "namespace environment mismatch: $namespace" >&2
    exit 2
  fi

  kubectl label namespace "$namespace" "jcode.io/course-id=$course_id" --overwrite >/dev/null
  kubectl annotate namespace "$namespace" "jcode.io/course-id=$course_id" --overwrite >/dev/null
  kubectl label namespace "$namespace" "jcode.io/environment=$environment" --overwrite >/dev/null
  kubectl annotate namespace "$namespace" "jcode.io/environment=$environment" --overwrite >/dev/null

  immutable=$(kubectl get configmap "$metadata_name" -n "$namespace" -o jsonpath='{.immutable}')
  if [[ "$immutable" != "true" ]]; then
    kubectl patch configmap "$metadata_name" -n "$namespace" --type=merge \
      -p '{"immutable":true}' >/dev/null
  fi
  echo "migrated $namespace"
done < <(kubectl get namespaces -o jsonpath='{range .items[*]}{.metadata.name}{"\n"}{end}')
