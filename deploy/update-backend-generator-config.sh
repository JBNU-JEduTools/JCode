#!/usr/bin/env bash
set -euo pipefail

namespace=${BACKEND_NAMESPACE:?BACKEND_NAMESPACE is required}
configmap=${BACKEND_CONFIGMAP:?BACKEND_CONFIGMAP is required}
bootstrap_url=${GENERATOR_BOOTSTRAP_URL:?GENERATOR_BOOTSTRAP_URL is required}
workspace_url=${GENERATOR_WORKSPACE_URL:?GENERATOR_WORKSPACE_URL is required}

for command in kubectl jq; do
  command -v "$command" >/dev/null || { echo "$command is required" >&2; exit 2; }
done

split_patch=$(jq -n \
  --arg bootstrap "$bootstrap_url" \
  --arg workspace "$workspace_url" \
  '{data:{GENERATOR_BOOTSTRAP_URL:$bootstrap,GENERATOR_WORKSPACE_URL:$workspace}}')
kubectl patch configmap "$configmap" -n "$namespace" --type=merge --patch "$split_patch"

config=$(kubectl get configmap "$configmap" -n "$namespace" -o json)
jq -e \
  --arg bootstrap "$bootstrap_url" \
  --arg workspace "$workspace_url" \
  '.data.GENERATOR_BOOTSTRAP_URL == $bootstrap and .data.GENERATOR_WORKSPACE_URL == $workspace' \
  <<<"$config" >/dev/null

if jq -e '.data | has("GENERATOR_URL")' <<<"$config" >/dev/null; then
  kubectl patch configmap "$configmap" -n "$namespace" --type=json \
    --patch '[{"op":"remove","path":"/data/GENERATOR_URL"}]'
fi

config=$(kubectl get configmap "$configmap" -n "$namespace" -o json)
jq -e \
  --arg bootstrap "$bootstrap_url" \
  --arg workspace "$workspace_url" \
  '.data.GENERATOR_BOOTSTRAP_URL == $bootstrap and
   .data.GENERATOR_WORKSPACE_URL == $workspace and
   (.data | has("GENERATOR_URL") | not)' \
  <<<"$config" >/dev/null
