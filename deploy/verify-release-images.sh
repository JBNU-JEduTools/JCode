#!/usr/bin/env bash
set -euo pipefail

manifest=${1:?release manifest path is required}
target=${2:?target must be dev or production}
[[ -f "$manifest" ]]
case "$target" in
  dev)
    jcode_namespace=dev
    watcher_namespace=${WATCHER_NAMESPACE:-dev}
    ;;
  prod|production)
    target=production
    jcode_namespace=watcher
    watcher_namespace=${WATCHER_NAMESPACE:-watcher}
    ;;
  *) echo "target must be dev or production: $target" >&2; exit 2 ;;
esac

digest_for() {
  jq -er --arg key "$1" '.digests[$key]' "$manifest"
}

allowed_runtime_digests() {
  local image=$1 expected=$2 raw child
  printf '%s\n' "$expected"
  raw=$(docker buildx imagetools inspect "$image@$expected" --raw)
  jq -r '.config.digest? // empty, .manifests[]?.digest' <<<"$raw"
  while IFS= read -r child; do
    [[ -n "$child" ]] || continue
    docker buildx imagetools inspect "$image@$child" --raw | jq -r '.config.digest? // empty'
  done < <(jq -r '.manifests[]?.digest' <<<"$raw")
}

verify_workload() {
  local kind=$1 namespace=$2 name=$3 container=$4 image=$5 expected=$6
  local workload selector pods spec_image allowed count
  workload=$(kubectl get "$kind" "$name" -n "$namespace" -o json)
  spec_image=$(jq -er --arg container "$container" '.spec.template.spec.containers[] | select(.name == $container) | .image' <<<"$workload")
  [[ "$spec_image" == "$image@$expected" ]] || {
    echo "$namespace/$kind/$name uses $spec_image, expected $image@$expected" >&2
    exit 1
  }
  selector=$(jq -r '.spec.selector.matchLabels | to_entries | map("\(.key)=\(.value)") | join(",")' <<<"$workload")
  pods=$(kubectl get pods -n "$namespace" -l "$selector" -o json)
  count=$(jq --arg container "$container" '[.items[].status.containerStatuses[]? | select(.name == $container and .ready == true)] | length' <<<"$pods")
  [[ "$count" -gt 0 ]] || { echo "$namespace/$kind/$name has no ready container" >&2; exit 1; }
  allowed=$(allowed_runtime_digests "$image" "$expected" | sort -u)
  while IFS= read -r image_id; do
    [[ -n "$image_id" ]] || continue
    actual=${image_id##*@}
    grep -Fxq "$actual" <<<"$allowed" || {
      echo "$namespace/$kind/$name imageID $actual is not derived from $expected" >&2
      exit 1
    }
  done < <(jq -r --arg container "$container" '.items[].status.containerStatuses[]? | select(.name == $container) | .imageID' <<<"$pods")
}

registry=harbor.jbnu.ac.kr/jdevops
verify_workload deployment "$jcode_namespace" jcode-bootstrap bootstrap "$registry/jcode-generator" "$(digest_for generator)"
verify_workload deployment "$jcode_namespace" jcode-generator jcode-generator "$registry/jcode-generator" "$(digest_for generator)"
verify_workload deployment "$jcode_namespace" jcode-router jcode-router "$registry/jcode-router" "$(digest_for router)"
verify_workload deployment "$jcode_namespace" squid-exporter squid-exporter "$registry/squid-exporter" "$(digest_for squid_exporter)"
verify_workload deployment "$watcher_namespace" watcher-backend watcher-backend "$registry/watcher-backend" "$(digest_for watcher_backend)"
verify_workload daemonset "$watcher_namespace" watcher-filemon watcher-filemon "$registry/watcher-filemon" "$(digest_for watcher_filemon)"
verify_workload daemonset "$watcher_namespace" watcher-procmon watcher-procmon "$registry/watcher-procmon" "$(digest_for watcher_procmon)"
verify_workload deployment "${BACKEND_NAMESPACE:?BACKEND_NAMESPACE is required}" "${BACKEND_DEPLOYMENT:?BACKEND_DEPLOYMENT is required}" "${BACKEND_CONTAINER:?BACKEND_CONTAINER is required}" "$registry/jcode-backend" "$(digest_for backend)"
verify_workload deployment "${FRONTEND_NAMESPACE:?FRONTEND_NAMESPACE is required}" "${FRONTEND_DEPLOYMENT:?FRONTEND_DEPLOYMENT is required}" "${FRONTEND_CONTAINER:?FRONTEND_CONTAINER is required}" "$registry/jcode-front" "$(digest_for frontend)"

generator_configmap=jcode-generator-configmap
[[ "$target" == dev ]] && generator_configmap=jcode-generator-dev-configmap
code_server=$(kubectl get configmap "$generator_configmap" -n "$jcode_namespace" -o jsonpath='{.data.CODE_SERVER_IMAGE}')
code_server_vnc=$(kubectl get configmap "$generator_configmap" -n "$jcode_namespace" -o jsonpath='{.data.CODE_SERVER_VNC_IMAGE}')
workspace_init=$(kubectl get configmap "$generator_configmap" -n "$jcode_namespace" -o jsonpath='{.data.WORKSPACE_INIT_IMAGE}')
[[ "$code_server" == "$registry/code-server@$(digest_for code_server)" ]]
[[ "$code_server_vnc" == "$registry/code-server-vnc@$(digest_for code_server_vnc)" ]]
[[ "$workspace_init" == "$registry/workspace-init@$(digest_for workspace_init)" ]]

echo "$target release images match the manifest"
