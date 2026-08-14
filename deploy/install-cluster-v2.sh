#!/usr/bin/env bash
set -euo pipefail

phase=${1:?phase must be prepare or finalize}
target=${2:?target must be dev or prod}
if [[ "$phase" != prepare && "$phase" != finalize ]]; then
  echo "phase must be prepare or finalize: $phase" >&2
  exit 2
fi
case "$target" in
  dev)
    metadata_policy=deploy/cluster/course-metadata-dev-policy.yaml
    ;;
  prod|production)
    target=prod
    metadata_policy=deploy/cluster/course-metadata-prod-policy.yaml
    if [[ "$phase" == prepare && ${CONFIRM_PROD_V2_PREPARE:-} != prod-prepare ]]; then
      echo "set CONFIRM_PROD_V2_PREPARE=prod-prepare before the production rollout" >&2
      exit 2
    fi
    if [[ "$phase" == finalize && ${CONFIRM_PROD_V2_FINALIZE:-} != prod-after-rollout ]]; then
      echo "set CONFIRM_PROD_V2_FINALIZE=prod-after-rollout after the production rollout" >&2
      exit 2
    fi
    ;;
  *)
    echo "target must be dev or prod: $target" >&2
    exit 2
    ;;
esac

if ! kubectl api-resources --api-group=admissionregistration.k8s.io -o name | grep -q '^validatingadmissionpolicies\.'; then
  echo "cluster does not support admissionregistration.k8s.io/v1 ValidatingAdmissionPolicy" >&2
  exit 2
fi

# prepare는 v2 권한을 추가할 뿐 기존 권한을 제거하지 않는다.
if [[ "$phase" == prepare ]]; then
  kubectl apply -k deploy/cluster
  if [[ "$target" == prod ]]; then
    deploy/migrate-workspace-rbac.sh prod
  else
    deploy/migrate-course-metadata.sh dev
    kubectl apply -f "$metadata_policy"
  fi
  echo "$target v2 cluster boundary prepared"
  exit 0
fi

if [[ "$target" == dev ]]; then
  echo "dev finalization is performed by deploy/cutover-dev.sh" >&2
  exit 2
fi

[[ $(kubectl get deployment jcode-generator -n watcher -o jsonpath='{.spec.template.spec.serviceAccountName}') == jcode-workspace-v2 ]]
[[ $(kubectl get deployment jcode-bootstrap -n watcher -o jsonpath='{.spec.template.spec.serviceAccountName}') == jcode-bootstrap-v2 ]]
deploy/migrate-course-metadata.sh prod
deploy/migrate-workspace-rbac.sh prod
kubectl apply -f "$metadata_policy"
deploy/finalize-workspace-rbac.sh prod

echo "production v2 permissions finalized"
