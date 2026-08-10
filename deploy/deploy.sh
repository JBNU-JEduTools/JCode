#!/usr/bin/env bash
set -euo pipefail

namespace=${JCODE_NAMESPACE:-watcher}
generator_digest=${GENERATOR_DIGEST:?GENERATOR_DIGEST is required}
router_digest=${ROUTER_DIGEST:?ROUTER_DIGEST is required}
code_server_digest=${CODE_SERVER_DIGEST:?CODE_SERVER_DIGEST is required}
code_server_vnc_digest=${CODE_SERVER_VNC_DIGEST:?CODE_SERVER_VNC_DIGEST is required}
workspace_init_digest=${WORKSPACE_INIT_DIGEST:?WORKSPACE_INIT_DIGEST is required}
squid_exporter_digest=${SQUID_EXPORTER_DIGEST:?SQUID_EXPORTER_DIGEST is required}

for digest in "$generator_digest" "$router_digest" "$code_server_digest" "$code_server_vnc_digest" "$workspace_init_digest" "$squid_exporter_digest"; do
  if [[ ! "$digest" =~ ^sha256:[0-9a-f]{64}$ ]]; then
    echo "invalid digest: $digest" >&2
    exit 2
  fi
done

for resource in \
  crd/externalsecrets.external-secrets.io \
  clustersecretstore/jcode-harbor-pull-secret \
  "configmap/squid-config" \
  "configmap/jcode-generator-configmap" \
  "secret/jcode-generator-secret" \
  "secret/watcher-harbor-registry-secret" \
  "persistentvolumeclaim/jcode-vol-pvc"; do
  case "$resource" in
    crd/*|clustersecretstore/*) kubectl get "$resource" >/dev/null ;;
    *) kubectl get "$resource" -n "$namespace" >/dev/null ;;
  esac
done

JCODE_NAMESPACE="$namespace" generator/k8s/configure-workspace-storage.sh

render_dir=$(mktemp -d)
trap 'rm -rf "$render_dir"' EXIT
python - "$namespace" "$generator_digest" "$router_digest" "$squid_exporter_digest" "$render_dir" <<'PY'
import sys
from pathlib import Path

namespace, generator_digest, router_digest, squid_exporter_digest, output = sys.argv[1:]
sources = (
    Path("generator/k8s/jcode-generator.yaml"),
    Path("generator/k8s/jcode-bootstrap-controller.yaml"),
    Path("router/k8s/jcode-router.yaml"),
    Path("router/k8s/squid-exporter.yaml"),
)
for source in sources:
    content = source.read_text(encoding="utf-8")
    content = content.replace("namespace: watcher", f"namespace: {namespace}")
    content = content.replace("      - watcher\n", f"      - {namespace}\n")
    content = content.replace(".watcher.svc.cluster.local", f".{namespace}.svc.cluster.local")
    content = content.replace(
        "harbor.jbnu.ac.kr/jdevops/jcode-generator:REPLACE_WITH_COMMIT_SHA",
        f"harbor.jbnu.ac.kr/jdevops/jcode-generator@{generator_digest}",
    )
    content = content.replace(
        "harbor.jbnu.ac.kr/jdevops/jcode-router:REPLACE_WITH_COMMIT_SHA",
        f"harbor.jbnu.ac.kr/jdevops/jcode-router@{router_digest}",
    )
    content = content.replace(
        "harbor.jbnu.ac.kr/jdevops/squid-exporter:REPLACE_WITH_COMMIT_SHA",
        f"harbor.jbnu.ac.kr/jdevops/squid-exporter@{squid_exporter_digest}",
    )
    (Path(output) / source.name).write_text(content, encoding="utf-8")
PY

kubectl apply -f "$render_dir/jcode-generator.yaml"
kubectl apply -f "$render_dir/jcode-bootstrap-controller.yaml"
kubectl apply -f "$render_dir/jcode-router.yaml"
kubectl apply -f "$render_dir/squid-exporter.yaml"

config_patch="$render_dir/generator-images.json"
printf '{"data":{"CODE_SERVER_IMAGE":"harbor.jbnu.ac.kr/jdevops/code-server@%s","CODE_SERVER_VNC_IMAGE":"harbor.jbnu.ac.kr/jdevops/code-server-vnc@%s","WORKSPACE_INIT_IMAGE":"harbor.jbnu.ac.kr/jdevops/workspace-init@%s"}}\n' \
  "$code_server_digest" "$code_server_vnc_digest" "$workspace_init_digest" > "$config_patch"
kubectl patch configmap jcode-generator-configmap -n "$namespace" --type=merge --patch-file "$config_patch"

kubectl rollout restart deployment/jcode-generator deployment/jcode-bootstrap -n "$namespace"
kubectl rollout status deployment/jcode-generator -n "$namespace" --timeout=5m
kubectl rollout status deployment/jcode-bootstrap -n "$namespace" --timeout=5m
kubectl rollout status deployment/jcode-router -n "$namespace" --timeout=5m
kubectl rollout status deployment/squid-exporter -n "$namespace" --timeout=5m
