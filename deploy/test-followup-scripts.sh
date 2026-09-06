#!/usr/bin/env bash
set -euo pipefail

repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
test_dir=$(mktemp -d)
trap 'rm -rf "$test_dir"' EXIT

mock_bin="$test_dir/bin"
state_dir="$test_dir/state"
mkdir -p "$mock_bin" "$state_dir"

cat > "$mock_bin/kubectl" <<'MOCK'
#!/usr/bin/env bash
set -euo pipefail

printf '%q ' "$@" >> "$MOCK_LOG"
printf '\n' >> "$MOCK_LOG"

if [[ ${MOCK_MODE:-} == storage ]]; then
  if [[ $1 == wait && $2 == -n ]]; then
    exit 0
  fi
  if [[ $1 == get && $2 == pvc ]]; then
    printf '%s' pvc-volume
    exit 0
  fi
  if [[ $1 == get && $2 == pv ]]; then
    case "$*" in
      *'.spec.nfs.server'*|*'.spec.nfs.path'*) exit 0 ;;
      *'.spec.csi.driver'*) printf '%s' driver.longhorn.io ;;
      *'.spec.csi.volumeHandle'*) printf '%s' pvc-11111111-2222-3333-4444-555555555555 ;;
      *) exit 2 ;;
    esac
    exit 0
  fi
  if [[ $1 == get && $2 == service ]]; then
    printf '%s' 10.233.9.148
    exit 0
  fi
  if [[ $1 == patch && $2 == configmap ]]; then
    while [[ $# -gt 0 ]]; do
      if [[ $1 == --patch ]]; then
        printf '%s' "$2" > "$MOCK_CONFIG"
        exit 0
      fi
      shift
    done
  fi
  exit 2
fi

if [[ ${MOCK_MODE:-} == config ]]; then
  if [[ $1 == patch && $2 == configmap ]]; then
    patch_type=
    patch=
    while [[ $# -gt 0 ]]; do
      case "$1" in
        --type=*) patch_type=${1#--type=} ;;
        --type) patch_type=$2; shift ;;
        --patch) patch=$2; shift ;;
      esac
      shift
    done
    if [[ $patch_type == merge ]]; then
      jq --argjson patch "$patch" '.data += $patch.data' "$MOCK_CONFIG" > "$MOCK_CONFIG.next"
    elif [[ $patch_type == json ]]; then
      jq 'del(.data.GENERATOR_URL)' "$MOCK_CONFIG" > "$MOCK_CONFIG.next"
    else
      exit 2
    fi
    mv "$MOCK_CONFIG.next" "$MOCK_CONFIG"
    exit 0
  fi
  if [[ $1 == get && $2 == configmap ]]; then
    cat "$MOCK_CONFIG"
    exit 0
  fi
  exit 2
fi

if [[ ${MOCK_MODE:-} != rbac ]]; then
  exit 2
fi

if [[ $1 == get && $2 == rolebindings ]]; then
  if [[ ${MOCK_MIXED_BINDING:-0} == 1 ]]; then
    cat <<'JSON'
{"items":[
  {"metadata":{"namespace":"jcode-os-1","name":"mixed-binding"},"subjects":[
    {"kind":"ServiceAccount","namespace":"watcher","name":"jcode-generator"},
    {"kind":"ServiceAccount","namespace":"watcher","name":"unrelated"}
  ]}
]}
JSON
  elif [[ -e "$MOCK_STATE/rolebindings-deleted" ]]; then
    printf '%s\n' '{"items":[]}'
  else
    cat <<'JSON'
{"items":[
  {"metadata":{"namespace":"jcode-os-1","name":"deployment-manager-binding"},"subjects":[{"kind":"ServiceAccount","namespace":"watcher","name":"jcode-generator"}]},
  {"metadata":{"namespace":"jcode-os-2","name":"workspace-binding"},"subjects":[{"kind":"ServiceAccount","namespace":"watcher","name":"jcode-workspace"}]},
  {"metadata":{"namespace":"jcode-dev-ignore-1","name":"dev-binding"},"subjects":[{"kind":"ServiceAccount","namespace":"watcher","name":"jcode-generator"}]},
  {"metadata":{"namespace":"jcode-safe-1","name":"unrelated-binding"},"subjects":[{"kind":"ServiceAccount","namespace":"watcher","name":"unrelated"}]}
]}
JSON
  fi
  exit 0
fi

if [[ $1 == get && $2 == clusterrolebindings ]]; then
  if [[ ${MOCK_MIXED_CLUSTER_BINDING:-0} == 1 ]]; then
    cat <<'JSON'
{"items":[
  {"metadata":{"name":"mixed-cluster-binding"},"subjects":[
    {"kind":"ServiceAccount","namespace":"watcher","name":"jcode-generator"},
    {"kind":"ServiceAccount","namespace":"watcher","name":"unrelated"}
  ]}
]}
JSON
  elif [[ -e "$MOCK_STATE/clusterrolebindings-deleted" ]]; then
    printf '%s\n' '{"items":[]}'
  else
    cat <<'JSON'
{"items":[
  {"metadata":{"name":"jcode-generator"},"subjects":[{"kind":"ServiceAccount","namespace":"watcher","name":"jcode-generator"}]},
  {"metadata":{"name":"namespace-reader-binding"},"subjects":[{"kind":"ServiceAccount","namespace":"watcher","name":"jcode-generator"}]},
  {"metadata":{"name":"jcode-workspace-namespace-reader"},"subjects":[{"kind":"ServiceAccount","namespace":"watcher","name":"jcode-workspace"}]},
  {"metadata":{"name":"jcode-bootstrap"},"subjects":[{"kind":"ServiceAccount","namespace":"watcher","name":"jcode-bootstrap"}]},
  {"metadata":{"name":"jcode-generator-binding"},"subjects":[{"kind":"ServiceAccount","namespace":"other","name":"jcode-generator"}]},
  {"metadata":{"name":"namespace-reader-binding-foreign"},"subjects":[{"kind":"ServiceAccount","namespace":"watcher","name":"jcode-generator"}]}
]}
JSON
  fi
  exit 0
fi

if [[ $1 == get && $2 == namespace ]]; then
  exit 0
fi
if [[ $1 == get && $2 == rolebinding && $3 == jcode-workspace-runtime-v2 ]]; then
  exit 0
fi
if [[ $1 == get && $2 == deployment ]]; then
  case "$3" in
    jcode-generator) printf '%s' jcode-workspace-v2 ;;
    jcode-bootstrap) printf '%s' jcode-bootstrap-v2 ;;
    *) exit 2 ;;
  esac
  exit 0
fi
if [[ $1 == auth && $2 == can-i ]]; then
  printf '%s\n' yes
  exit 0
fi
if [[ $1 == delete && $2 == rolebinding ]]; then
  touch "$MOCK_STATE/rolebindings-deleted"
  exit 0
fi
if [[ $1 == delete && $2 == clusterrolebinding ]]; then
  touch "$MOCK_STATE/clusterrolebindings-deleted"
  exit 0
fi
if [[ $1 == delete && $2 == serviceaccount ]]; then
  exit 0
fi
exit 2
MOCK
chmod +x "$mock_bin/kubectl"

export PATH="$mock_bin:$PATH"
export MOCK_LOG="$state_dir/kubectl.log"

config_file="$state_dir/backend-config.json"
cat > "$config_file" <<'JSON'
{"data":{"GENERATOR_URL":"http://legacy:5000","KEEP":"value"}}
JSON
export MOCK_MODE=config
export MOCK_CONFIG="$config_file"

for _ in 1 2; do
  BACKEND_NAMESPACE=dev \
    BACKEND_CONFIGMAP=jcode-backend-config \
    GENERATOR_BOOTSTRAP_URL=http://jcode-bootstrap-svc:5000 \
    GENERATOR_WORKSPACE_URL=http://jcode-generator-svc:5000 \
    "$repo_root/deploy/update-backend-generator-config.sh"
done

jq -e '
  .data.GENERATOR_BOOTSTRAP_URL == "http://jcode-bootstrap-svc:5000" and
  .data.GENERATOR_WORKSPACE_URL == "http://jcode-generator-svc:5000" and
  .data.KEEP == "value" and
  (.data | has("GENERATOR_URL") | not)
' "$config_file" >/dev/null
[[ $(grep -c '/data/GENERATOR_URL' "$MOCK_LOG") -eq 1 ]]

: > "$MOCK_LOG"
export MOCK_MODE=storage
storage_patch="$state_dir/storage-patch.json"
export MOCK_CONFIG="$storage_patch"
JCODE_NAMESPACE=watcher GENERATOR_CONFIGMAP_NAME=jcode-generator-configmap \
  "$repo_root/generator/k8s/configure-workspace-storage.sh"
jq -e '
  .data.NFS_SERVER == "10.233.9.148" and
  .data.NFS_PATH == "/pvc-11111111-2222-3333-4444-555555555555" and
  .data.NFS_MOUNT_PATH == "/nfs-data" and
  .data.WORKSPACE_EXTENSIONS_DIR == "extensions-v2"
' "$storage_patch" >/dev/null
grep -q 'get service pvc-11111111-2222-3333-4444-555555555555' "$MOCK_LOG"

: > "$MOCK_LOG"
export MOCK_MODE=rbac
export MOCK_STATE="$state_dir"
"$repo_root/deploy/finalize-workspace-rbac.sh" prod
"$repo_root/deploy/finalize-workspace-rbac.sh" prod

grep -q 'delete rolebinding deployment-manager-binding -n jcode-os-1 --ignore-not-found' "$MOCK_LOG"
grep -q 'delete rolebinding workspace-binding -n jcode-os-2 --ignore-not-found' "$MOCK_LOG"
grep -q 'delete clusterrolebinding jcode-generator --ignore-not-found' "$MOCK_LOG"
grep -q 'delete clusterrolebinding namespace-reader-binding --ignore-not-found' "$MOCK_LOG"
grep -q 'delete clusterrolebinding jcode-workspace-namespace-reader --ignore-not-found' "$MOCK_LOG"
grep -q 'delete clusterrolebinding namespace-reader-binding-foreign --ignore-not-found' "$MOCK_LOG"
grep -q 'delete serviceaccount jcode-generator jcode-workspace jcode-bootstrap -n watcher --ignore-not-found' "$MOCK_LOG"
if grep -q 'delete rolebinding dev-binding\|delete rolebinding unrelated-binding\|delete clusterrolebinding jcode-generator-binding' "$MOCK_LOG"; then
  echo "unrelated binding was selected for deletion" >&2
  exit 1
fi

rm -f "$state_dir/rolebindings-deleted"
: > "$MOCK_LOG"
if MOCK_MIXED_BINDING=1 "$repo_root/deploy/finalize-workspace-rbac.sh" prod >/dev/null 2>&1; then
  echo "mixed-subject RoleBinding was accepted" >&2
  exit 1
fi
if grep -q '^delete ' "$MOCK_LOG"; then
  echo "cleanup started before mixed-subject validation completed" >&2
  exit 1
fi

touch "$state_dir/rolebindings-deleted"
rm -f "$state_dir/clusterrolebindings-deleted"
: > "$MOCK_LOG"
if MOCK_MIXED_CLUSTER_BINDING=1 "$repo_root/deploy/finalize-workspace-rbac.sh" prod >/dev/null 2>&1; then
  echo "mixed-subject ClusterRoleBinding was accepted" >&2
  exit 1
fi
if grep -q '^delete ' "$MOCK_LOG"; then
  echo "cleanup started before mixed ClusterRoleBinding validation completed" >&2
  exit 1
fi

trigger=$(sed -n '/^on:/,/^permissions:/p' "$repo_root/.github/workflows/images.yaml")
grep -q '^  pull_request:' <<<"$trigger"
if grep -q '^  push:' <<<"$trigger"; then
  echo "images workflow must not run on develop push" >&2
  exit 1
fi
grep -q 'push: false' "$repo_root/.github/workflows/images.yaml"
grep -q 'update-backend-generator-config.sh' "$repo_root/deploy/cutover-dev.sh"

echo "follow-up deployment script tests passed"
