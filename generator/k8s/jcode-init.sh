#!/bin/bash
# jcode-init.sh

# 사용법: ./jcode-init.sh <namespace>
if [ "$#" -ne 1 ]; then
  echo "Usage: $0 <namespace>"
  exit 1
fi

export NAMESPACE=$1

cat <<'EOF' | envsubst > jcode-init.yaml
---
# 1. 네임스페이스 생성
apiVersion: v1
kind: Namespace
metadata:
  name: ${NAMESPACE}
  labels:
    role: jcode

---
# 2. 서비스 어카운트 생성 (추후 배포되는 WebIDE 파드가 사용할 계정) => 현재 권한 X
apiVersion: v1
kind: ServiceAccount
metadata:
  name: deployment-controller
  namespace: ${NAMESPACE}

---
# 3. Role 생성: ${NAMESPACE} 네임스페이스 내에서 Deployment, Service, ConfigMap, Secret 등에 대한 권한 부여
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: deployment-manager
  namespace: ${NAMESPACE}
rules:
- apiGroups: ["apps"]
  resources: ["deployments"]
  verbs: ["create", "get", "list", "watch", "update", "patch", "delete"]
- apiGroups: [""]
  resources: ["services"]
  verbs: ["create", "get", "list", "watch", "update", "patch", "delete"]
- apiGroups: [""]
  resources: ["configmaps"]
  verbs: ["get", "list", "watch"]
- apiGroups: [""]
  resources: ["secrets"]
  verbs: ["get", "list", "watch"]
  
---
# 4. RoleBinding 생성: 위 Role을 서비스 어카운트에 바인딩
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: deployment-manager-binding
  namespace: ${NAMESPACE}
subjects:
- kind: ServiceAccount
  name: jcode-generator
  namespace: watcher
roleRef:
  kind: Role
  name: deployment-manager
  apiGroup: rbac.authorization.k8s.io
---
# 5. code-server-config.yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: code-server-config
  namespace: ${NAMESPACE}
data:
  config.yaml: |
    bind-addr: 127.0.0.1:8080
    auth: none
    cert: false
---
# 6. Limit Range 설정
apiVersion: v1
kind: LimitRange
metadata:
  name: pod-resource-limits
  namespace: ${NAMESPACE}
spec:
  limits:
  - type: Container
    defaultRequest:
      cpu: "200m"
      memory: "256Mi"
    default:
      cpu: "4"
      memory: "2Gi"
---
# 7. Network Policy 설정 (watcher & jcode 통신  +++  ingress, pormetheus(monitoring))
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: watcher-networkpolicy
  namespace: ${NAMESPACE}
spec:
  podSelector: {}  # 모든 파드에 적용 (필요에 따라 특정 라벨 선택 가능)
  ingress:
  - from:
    - namespaceSelector:
        matchLabels:
          role: jcode  # jcode 네임스페이스에 부여한 라벨
    - namespaceSelector:
        matchLabels:
          kubernetes.io/metadata.name: watcher
    - namespaceSelector:
        matchLabels:
          kubernetes.io/metadata.name: monitoring
    - namespaceSelector:
        matchLabels:
          kubernetes.io/metadata.name: ingress-nginx
  policyTypes:
  - Ingress
EOF

echo "Applying Jcode init in namespace ${NAMESPACE}..."
kubectl apply -f jcode-init.yaml
