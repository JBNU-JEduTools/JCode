#!/usr/bin/env bash
set -euo pipefail

target=${1:-dev}
workspace_url=${WORKSPACE_URL:?WORKSPACE_URL is required}
run_number=${GITHUB_RUN_ID:-999999}
class_number=${run_number: -9}
[[ "$class_number" =~ ^[0-9]+$ ]]

case "$target" in
  dev)
    controller_namespace=dev
    generator_secret=jcode-generator-dev-secret
    bootstrap_url=${BOOTSTRAP_URL:?BOOTSTRAP_URL is required for dev smoke test}
    course_id=2147000000
    request_namespace="jcode-release-${class_number}"
    actual_namespace="jcode-dev-release-${class_number}"
    delete_namespace=true
    ;;
  prod|production)
    target=production
    controller_namespace=watcher
    generator_secret=jcode-generator-secret
    actual_namespace=${SMOKE_COURSE_NAMESPACE:?SMOKE_COURSE_NAMESPACE is required for production}
    [[ "$actual_namespace" == jcode-* && "$actual_namespace" != jcode-dev-* ]] || {
      echo "no production course namespace is available for the smoke test" >&2
      exit 2
    }
    kubectl get rolebinding jcode-workspace-runtime-v2 -n "$actual_namespace" >/dev/null
    course_id=$(kubectl get configmap jcode-course-metadata -n "$actual_namespace" -o jsonpath='{.data.course-id}')
    [[ "$course_id" =~ ^[1-9][0-9]*$ ]]
    request_namespace=$actual_namespace
    delete_namespace=false
    ;;
  *)
    echo "target must be dev or production: $target" >&2
    exit 2
    ;;
esac

deployment_name="jcode-release-${class_number}-smoke"
service_name="jcode-release-${class_number}-smoke"
file_path="workspace/release-smoke/${deployment_name}"
student_num="release-smoke-${class_number}"
workspace_created=false
nfs_prepared=false
port_forward_pid=

# shellcheck source=deploy/generator-token.sh
source "$(dirname "$0")/generator-token.sh"
load_generator_service_secret "$controller_namespace" "$generator_secret"

delete_workspace() {
  token=$(create_generator_token jcode:delete)
  delete_body=$(jq -n \
    --arg namespace "$request_namespace" \
    --arg deployment_name "$deployment_name" \
    --arg service_name "$service_name" \
    --argjson course_id "$course_id" \
    '{course_id:$course_id,namespace:$namespace,deployment_name:$deployment_name,service_name:$service_name}')
  curl --fail-with-body --silent --show-error --request DELETE \
    -H "Authorization: Bearer $token" \
    -H 'Content-Type: application/json' \
    --data "$delete_body" \
    "$workspace_url/api/jcode" >/dev/null
}

delete_smoke_nfs() {
  token=$(create_generator_token workspace:smoke)
  curl --fail-with-body --silent --show-error --request DELETE \
    -H "Authorization: Bearer $token" \
    -H 'Content-Type: application/json' \
    --data "$smoke_body" \
    "$workspace_url/api/workspace/smoke" >/dev/null
}

cleanup() {
  [[ -z "$port_forward_pid" ]] || kill "$port_forward_pid" 2>/dev/null || true
  if [[ "$workspace_created" == true ]]; then
    delete_workspace || true
  fi
  if [[ "$nfs_prepared" == true ]]; then
    delete_smoke_nfs || true
  fi
  if [[ "$delete_namespace" == true ]]; then
    token=$(create_generator_token namespace:delete)
    curl --silent --show-error --request DELETE \
      -H "Authorization: Bearer $token" \
      "${bootstrap_url}/api/namespace/${request_namespace}?course_id=${course_id}" >/dev/null || true
  fi
}
trap cleanup EXIT

if [[ "$target" == dev ]]; then
  token=$(create_generator_token namespace:write)
  body=$(jq -n \
    --arg namespace "$request_namespace" \
    --argjson course_id "$course_id" \
    '{namespace:$namespace,course_id:$course_id,use_vnc:false}')
  response=$(curl --fail-with-body --silent --show-error \
    -H "Authorization: Bearer $token" \
    -H 'Content-Type: application/json' \
    --data "$body" \
    "$bootstrap_url/api/namespace")
  [[ $(jq -r '.namespace' <<<"$response") == "$actual_namespace" ]]
fi

smoke_body=$(jq -n \
  --arg namespace "$request_namespace" \
  --arg file_path "$file_path" \
  --arg student_num "$student_num" \
  --argjson course_id "$course_id" \
  '{course_id:$course_id,namespace:$namespace,file_path:$file_path,student_num:$student_num}')
nfs_prepared=true
token=$(create_generator_token workspace:smoke)
curl --fail-with-body --silent --show-error \
  -H "Authorization: Bearer $token" \
  -H 'Content-Type: application/json' \
  --data "$smoke_body" \
  "$workspace_url/api/workspace/smoke" >/dev/null

token=$(create_generator_token jcode:write)
body=$(jq -n \
  --arg namespace "$request_namespace" \
  --arg deployment_name "$deployment_name" \
  --arg service_name "$service_name" \
  --arg file_path "$file_path" \
  --arg student_num "$student_num" \
  --argjson course_id "$course_id" \
  '{
    course_id:$course_id,
    namespace:$namespace,
    deployment_name:$deployment_name,
    service_name:$service_name,
    app_label:$deployment_name,
    file_path:$file_path,
    student_num:$student_num,
    use_vnc:false,
    use_snapshot:false,
    hw_count:0,
    prac_count:0,
    assignment_dirs:[]
  }')
workspace_created=true
curl --fail-with-body --silent --show-error \
  -H "Authorization: Bearer $token" \
  -H 'Content-Type: application/json' \
  --data "$body" \
  "$workspace_url/api/jcode" >/dev/null

kubectl rollout status deployment/"$deployment_name" -n "$actual_namespace" --timeout=5m
kubectl wait pod -n "$actual_namespace" -l "app=$deployment_name" --for=condition=Ready --timeout=5m
deployment=$(kubectl get deployment "$deployment_name" -n "$actual_namespace" -o json)
jq -e --arg file_path "$file_path" '
  any(.spec.template.spec.volumes[]?; .name == "jcode-vol" and (.nfs.server | length > 0) and (.nfs.path | length > 0)) and
  any(.spec.template.spec.initContainers[].volumeMounts[]?; .name == "jcode-vol" and .subPath == $file_path) and
  any(.spec.template.spec.containers[].volumeMounts[]?; .name == "jcode-vol" and .subPath == $file_path)
' <<<"$deployment" >/dev/null
pod=$(kubectl get pods -n "$actual_namespace" -l "app=$deployment_name" -o json)
jq -e '
  (.items | length) > 0 and
  all(.items[].status.initContainerStatuses[]?; .state.terminated.exitCode == 0) and
  all(.items[].status.containerStatuses[]?; .ready == true)
' <<<"$pod" >/dev/null

local_port=$((18000 + run_number % 1000))
kubectl port-forward -n "$actual_namespace" "service/$service_name" "$local_port:8080" \
  >"${RUNNER_TEMP:-/tmp}/workspace-smoke-port-forward.log" 2>&1 &
port_forward_pid=$!
for _ in $(seq 1 60); do
  curl --fail --silent --output /dev/null "http://127.0.0.1:${local_port}/healthz" && break
  sleep 2
done
curl --fail --silent --output /dev/null "http://127.0.0.1:${local_port}/healthz"
kill "$port_forward_pid" 2>/dev/null || true
port_forward_pid=

delete_workspace
for _ in $(seq 1 60); do
  if ! kubectl get deployment "$deployment_name" -n "$actual_namespace" >/dev/null 2>&1 && \
     ! kubectl get service "$service_name" -n "$actual_namespace" >/dev/null 2>&1 && \
     [[ $(kubectl get pods -n "$actual_namespace" -l "app=$deployment_name" -o json | jq '.items | length') -eq 0 ]]; then
    break
  fi
  sleep 2
done
if kubectl get deployment "$deployment_name" -n "$actual_namespace" >/dev/null 2>&1 || \
   kubectl get service "$service_name" -n "$actual_namespace" >/dev/null 2>&1 || \
   [[ $(kubectl get pods -n "$actual_namespace" -l "app=$deployment_name" -o json | jq '.items | length') -ne 0 ]]; then
  echo "workspace smoke resources were not deleted" >&2
  exit 1
fi
workspace_created=false
delete_smoke_nfs
nfs_prepared=false

if [[ "$delete_namespace" == true ]]; then
  token=$(create_generator_token namespace:delete)
  curl --fail-with-body --silent --show-error --request DELETE \
    -H "Authorization: Bearer $token" \
    "${bootstrap_url}/api/namespace/${request_namespace}?course_id=${course_id}" >/dev/null
  delete_namespace=false
  if kubectl get namespace "$actual_namespace" >/dev/null 2>&1; then
    echo "smoke namespace still exists: $actual_namespace" >&2
    exit 1
  fi
fi

trap - EXIT
echo "$target workspace lifecycle smoke test passed: $actual_namespace"
