#!/usr/bin/env bash
set -euo pipefail

external_secrets_version=${EXTERNAL_SECRETS_VERSION:-2.9.0}
source_namespace=watcher
target_namespace=${JCODE_NAMESPACE:-watcher}

for command in kubectl helm jq python3; do
  command -v "$command" >/dev/null || { echo "$command is required" >&2; exit 2; }
done

kubectl create namespace "$source_namespace" --dry-run=client -o yaml | kubectl apply -f -
kubectl create namespace "$target_namespace" --dry-run=client -o yaml | kubectl apply -f -
helm repo add external-secrets https://charts.external-secrets.io --force-update
helm repo update external-secrets
helm upgrade --install external-secrets external-secrets/external-secrets \
  --namespace external-secrets \
  --create-namespace \
  --version "$external_secrets_version" \
  --set installCRDs=true \
  --wait \
  --timeout 10m

kubectl wait --for=condition=Established crd/externalsecrets.external-secrets.io --timeout=2m
kubectl wait --for=condition=Established crd/clustersecretstores.external-secrets.io --timeout=2m
kubectl get secret watcher-harbor-registry-secret -n "$source_namespace" >/dev/null
kubectl apply -f generator/k8s/harbor-external-secret-store.yaml
kubectl wait --for=condition=Ready clustersecretstore/jcode-harbor-pull-secret --timeout=2m

if [[ "$target_namespace" != "$source_namespace" ]]; then
  cat <<EOF | kubectl apply -f -
apiVersion: external-secrets.io/v1
kind: ExternalSecret
metadata:
  name: watcher-harbor-registry-secret-sync
  namespace: ${target_namespace}
spec:
  refreshInterval: 1h
  secretStoreRef:
    name: jcode-harbor-pull-secret
    kind: ClusterSecretStore
  target:
    name: watcher-harbor-registry-secret
    creationPolicy: Owner
    template:
      type: kubernetes.io/dockerconfigjson
  dataFrom:
    - extract:
        key: watcher-harbor-registry-secret
EOF
  kubectl wait -n "$target_namespace" \
    --for=condition=Ready \
    externalsecret/watcher-harbor-registry-secret-sync \
    --timeout=2m
fi
kubectl get secret watcher-harbor-registry-secret -n "$target_namespace" >/dev/null

ROUTER_NAMESPACE="$target_namespace" \
  ALLOWED_NETWORK_CIDR="${ALLOWED_NETWORK_CIDR:?ALLOWED_NETWORK_CIDR is required}" \
  HTTP_PORT="${HTTP_PORT:-3000}" \
  router/k8s/configure-squid.sh
