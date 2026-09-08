#!/usr/bin/env bash
set -euo pipefail

expected_context=${EXPECTED_TEST_CONTEXT:-kind-jcode-policy}
actual_context=$(kubectl config current-context)
if [[ "$actual_context" != "$expected_context" ]]; then
  echo "refusing to run outside the isolated test cluster: $actual_context" >&2
  exit 2
fi

suffix=${GITHUB_RUN_ID:-local}-$$
dev_namespace="jcode-dev-policy-e2e-$suffix"
prod_namespace="jcode-policy-e2e-$suffix"

cleanup() {
  kubectl delete namespace "$dev_namespace" "$prod_namespace" dev watcher \
    --ignore-not-found --wait=false >/dev/null 2>&1 || true
}
trap cleanup EXIT

kubectl apply -f deploy/cluster/course-metadata-dev-policy.yaml >/dev/null
kubectl apply -f deploy/cluster/course-metadata-prod-policy.yaml >/dev/null
kubectl create namespace dev >/dev/null
kubectl create namespace watcher >/dev/null
kubectl create serviceaccount jcode-bootstrap-v2 -n dev >/dev/null
kubectl create serviceaccount jcode-bootstrap-v2 -n watcher >/dev/null

verify_namespace_lifecycle() {
  local namespace=$1 environment=$2 controller_namespace=$3
  kubectl create namespace "$namespace" >/dev/null
  kubectl create role metadata-writer -n "$namespace" \
    --verb=create,update,patch,delete --resource=configmaps >/dev/null
  kubectl create rolebinding metadata-writer -n "$namespace" \
    --role=metadata-writer --serviceaccount="$controller_namespace:jcode-bootstrap-v2" >/dev/null

  kubectl create --as="system:serviceaccount:$controller_namespace:jcode-bootstrap-v2" -f - >/dev/null <<EOF
apiVersion: v1
kind: ConfigMap
metadata:
  name: jcode-course-metadata
  namespace: $namespace
immutable: true
data:
  course-id: "1"
  namespace: $namespace
  environment: $environment
EOF

  # 새 API 서버에서는 AdmissionPolicy informer가 Binding을 반영하는 데 잠시 걸릴 수 있다.
  # 직접 삭제가 실제로 거부될 때까지 metadata를 복원하며 확인한다.
  local protected=false
  for _ in $(seq 1 30); do
    if ! kubectl delete configmap jcode-course-metadata -n "$namespace" >/dev/null 2>&1; then
      protected=true
      break
    fi
    kubectl create --as="system:serviceaccount:$controller_namespace:jcode-bootstrap-v2" -f - >/dev/null <<EOF
apiVersion: v1
kind: ConfigMap
metadata:
  name: jcode-course-metadata
  namespace: $namespace
immutable: true
data:
  course-id: "1"
  namespace: $namespace
  environment: $environment
EOF
    sleep 1
  done
  if [[ "$protected" != true ]]; then
    echo "direct metadata deletion unexpectedly succeeded: $namespace" >&2
    return 1
  fi

  kubectl delete namespace "$namespace" --wait=false >/dev/null
  for _ in $(seq 1 90); do
    if ! kubectl get namespace "$namespace" >/dev/null 2>&1; then
      return 0
    fi
    sleep 1
  done
  echo "namespace deletion did not complete: $namespace" >&2
  kubectl get namespace "$namespace" -o yaml >&2 || true
  return 1
}

verify_namespace_lifecycle "$dev_namespace" dev dev
verify_namespace_lifecycle "$prod_namespace" prod watcher
