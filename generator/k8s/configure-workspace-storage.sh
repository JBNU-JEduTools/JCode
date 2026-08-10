#!/usr/bin/env bash
set -euo pipefail

namespace=${JCODE_NAMESPACE:-watcher}
pvc_name=${WORKSPACE_PVC_NAME:-jcode-vol-pvc}

kubectl wait -n "$namespace" \
  --for=jsonpath='{.status.phase}'=Bound \
  "pvc/${pvc_name}" \
  --timeout=3m

volume_name=$(kubectl get pvc "$pvc_name" -n "$namespace" -o jsonpath='{.spec.volumeName}')
test -n "$volume_name"

nfs_server=$(kubectl get pv "$volume_name" -o jsonpath='{.spec.nfs.server}')
nfs_path=$(kubectl get pv "$volume_name" -o jsonpath='{.spec.nfs.path}')

if [[ -z "$nfs_server" || -z "$nfs_path" ]]; then
  csi_driver=$(kubectl get pv "$volume_name" -o jsonpath='{.spec.csi.driver}')
  volume_handle=$(kubectl get pv "$volume_name" -o jsonpath='{.spec.csi.volumeHandle}')
  if [[ "$csi_driver" != "driver.longhorn.io" || ! "$volume_handle" =~ ^pvc-[0-9a-f-]+$ ]]; then
    echo "PVC must use an NFS PV or a Longhorn RWX volume" >&2
    exit 1
  fi
  nfs_server="${volume_handle}.longhorn-system.svc.cluster.local"
  nfs_path="/${volume_handle}"
  kubectl get service "$volume_handle" -n longhorn-system >/dev/null
fi

patch=$(jq -n \
  --arg server "$nfs_server" \
  --arg path "$nfs_path" \
  '{data:{NFS_SERVER:$server,NFS_PATH:$path,NFS_MOUNT_PATH:"/nfs-data"}}')
kubectl patch configmap jcode-generator-configmap \
  -n "$namespace" \
  --type=merge \
  --patch "$patch"

echo "Configured ${namespace}/jcode-generator-configmap from ${namespace}/${pvc_name}"
