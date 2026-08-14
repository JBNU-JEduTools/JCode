# JCode 배포 구성

`deploy/cluster`에는 기존 운영 권한과 충돌하지 않는 v2 ClusterRole과 AdmissionPolicy가 있습니다.
`deploy/base`에는 Generator, Bootstrap, Router, Squid Exporter의 공통 리소스가 있습니다.
환경 차이는 다음 overlay에서만 관리합니다.

- `deploy/overlays/dev`: `dev`, 단일 replica, dev node 배치, HPA 없음
- `deploy/overlays/prod`: `watcher`, Router·Generator 다중 replica, HPA와 PDB 적용

두 환경 모두 Bootstrap과 Workspace Controller를 별도 Deployment와 ServiceAccount로 실행합니다.
ClusterRoleBinding 이름은 환경별로 분리되어 같은 클러스터에 함께 배포해도 서로 덮어쓰지 않습니다.
dev course namespace는 `jcode-dev-*`, production은 `jcode-*`를 사용합니다.
운영 배포는 개발 배포에서 만든 release manifest의 저장소 revision과 Harbor digest를 그대로 사용하며 이미지를 다시 만들지 않습니다.

## 자동 전환 순서

1. 통합 release workflow가 dev v2 권한을 준비하고 새 컨트롤러를 병행 배포합니다.
2. `Switch dev controllers` workflow는 release manifest의 커밋을 checkout하고 실행 중인 이미지 식별값을 확인합니다.
3. 기존 dev 강의를 `jcode-dev-*`로 초기화하고 workspace 생성·삭제 시험을 통과한 뒤 Backend·Ingress를 전환합니다.
4. v2 권한을 확인한 후 구형 RoleBinding·ServiceAccount·Deployment·Service를 제거합니다.
5. production release는 성공한 dev 전환 결과만 입력으로 받습니다. v2 권한 준비 → rollout → 구형 권한 정리를 순서대로 실행합니다.

dev overlay는 기존 `jcode-generator-dev-*`, `jcode-router-dev-*` ConfigMap과 Secret을 참조합니다.
`deploy/deploy.sh` 자체는 ClusterRole이나 전역 정책을 변경하지 않습니다. 통합 release의 별도 단계가 권한 준비와 정리를 담당합니다.
자동 배포는 통합 release에서 권한과 배포 순서를 관리합니다.

## 수동 배포 순서

수동 배포도 자동 배포와 같은 commit의 이미지 digest를 사용하며 production에서 이미지를 다시 만들지 않습니다.

1. Harbor에서 배포할 commit SHA와 이미지 digest를 확인합니다.

   ```bash
   export COMMIT_SHA=<배포할-commit-sha>
   docker buildx imagetools inspect "harbor.jbnu.ac.kr/jdevops/jcode-generator:$COMMIT_SHA"
   ```

   같은 방법으로 `jcode-router`, `code-server`, `code-server-vnc`, `workspace-init`, `squid-exporter`, Watcher 3개 이미지, Backend, Frontend를 확인합니다.

2. 대상 환경의 v2 권한을 준비합니다.

   ```bash
   deploy/install-cluster-v2.sh prepare dev

   # production
   CONFIRM_PROD_V2_PREPARE=prod-prepare deploy/install-cluster-v2.sh prepare prod
   ```

3. Harbor에서 확인한 digest를 설정합니다. 모든 값은 `sha256:`으로 시작하는 64자리 digest여야 합니다.

   ```bash
   export GENERATOR_DIGEST=<jcode-generator-digest>
   export ROUTER_DIGEST=<jcode-router-digest>
   export CODE_SERVER_DIGEST=<code-server-digest>
   export CODE_SERVER_VNC_DIGEST=<code-server-vnc-digest>
   export WORKSPACE_INIT_DIGEST=<workspace-init-digest>
   export SQUID_EXPORTER_DIGEST=<squid-exporter-digest>
   export WATCHER_BACKEND_DIGEST=<watcher-backend-digest>
   export WATCHER_FILEMON_DIGEST=<watcher-filemon-digest>
   export WATCHER_PROCMON_DIGEST=<watcher-procmon-digest>
   export BACKEND_DIGEST=<backend-digest>
   export FRONTEND_DIGEST=<frontend-digest>
   export ALLOWED_NETWORK_CIDR=<해당-환경의-workspace-pod-cidr>
   ```

4. Watcher → Generator·Router → Backend → Frontend 순서로 같은 환경에 배포합니다. production의 기존 Router에 노드 고정이 남아 있으면 최초 전환 전에 한 번 제거합니다.

   ```bash
   export TARGET_ENV=dev  # production 배포는 production으로 설정
   export BACKEND_NAMESPACE=<backend-namespace>
   export BACKEND_DEPLOYMENT=<backend-deployment>
   export BACKEND_CONTAINER=<backend-container>
   export FRONTEND_NAMESPACE=<frontend-namespace>
   export FRONTEND_DEPLOYMENT=<frontend-deployment>
   export FRONTEND_CONTAINER=<frontend-container>

   # 기존 production Router 전환 시 deploy/deploy.sh보다 먼저 한 번만 실행
   if [[ "$TARGET_ENV" == production ]]; then
     kubectl patch deployment jcode-router -n watcher --type=merge \
       -p '{"spec":{"template":{"spec":{"nodeSelector":null}}}}'
   fi

   (
     cd ../JCode-Watcher
     python deploy/set-image-digests.py "$TARGET_ENV" \
       "$WATCHER_BACKEND_DIGEST" "$WATCHER_FILEMON_DIGEST" "$WATCHER_PROCMON_DIGEST"
     deploy/deploy.sh "$TARGET_ENV"
   )

   deploy/deploy.sh "$TARGET_ENV"

   kubectl set image "deployment/$BACKEND_DEPLOYMENT" \
     "$BACKEND_CONTAINER=harbor.jbnu.ac.kr/jdevops/jcode-backend@$BACKEND_DIGEST" \
     -n "$BACKEND_NAMESPACE"
   kubectl rollout status "deployment/$BACKEND_DEPLOYMENT" -n "$BACKEND_NAMESPACE" --timeout=5m

   kubectl set image "deployment/$FRONTEND_DEPLOYMENT" \
     "$FRONTEND_CONTAINER=harbor.jbnu.ac.kr/jdevops/jcode-front@$FRONTEND_DIGEST" \
     -n "$FRONTEND_NAMESPACE"
   kubectl rollout status "deployment/$FRONTEND_DEPLOYMENT" -n "$FRONTEND_NAMESPACE" --timeout=5m
   ```

5. dev는 smoke test를 포함한 controller 전환을 실행합니다. production은 기존 강의로 Workspace 생성·기동·IDE 응답·삭제를 확인합니다.

   ```bash
   CONFIRM_DEV_CUTOVER=dev \
   BACKEND_NAMESPACE=dev \
   BACKEND_DEPLOYMENT=<dev-backend-deployment> \
     deploy/cutover-dev.sh

   # production
   WORKSPACE_URL=<workspace-generator-url> \
   SMOKE_COURSE_NAMESPACE=<검증할-production-course-namespace> \
     deploy/smoke-workspace-lifecycle.sh production
   ```

6. production smoke test가 성공한 뒤에만 구형 권한을 정리합니다.

   ```bash
   CONFIRM_PROD_V2_FINALIZE=prod-after-rollout \
     deploy/install-cluster-v2.sh finalize prod
   ```

Router ConfigMap의 `CORS_ORIGIN`과 `COOKIE_DOMAIN`은 예시값을 그대로 쓰지 말고 실제 서비스 도메인으로 설정해야 합니다.
`ALLOWED_NETWORK_CIDR`은 해당 환경의 Workspace Pod 출발지 CIDR로 설정합니다. 배포 스크립트는 이 값으로 `squid-config`를 다시 만들고 cache-manager ACL까지 확인합니다.
Kubernetes NetworkPolicy는 여러 정책의 허용 규칙이 합산됩니다. 외부 클러스터 설정에 같은 Pod를 넓게 허용하는 정책이 있으면 이 저장소의 제한 정책이 무력화되므로, 해당 정책도 클러스터 설정의 source-of-truth에서 제거하거나 범위를 축소해야 합니다.

course metadata가 없는 기존 Namespace는 `deploy/legacy-namespace-plan.json`에 환경별로 명시합니다.
`jcode-dev-1`과 production의 `jcode-jct-1`은 기존 workload와 Namespace를 유지하고 구형 컨트롤러 권한만 회수하는 격리 대상입니다.
ACTIVE 강좌인 `jcode-realtest2-1`과 `jcode-test2502-1`은 각각 course ID 6과 1로 새 dev Namespace를 만듭니다. 기존 세션 workload는 복사하지 않고 제거하며, NFS 데이터는 유지한 채 다음 접속에서 새 Namespace에 재생성합니다.
실제 강의라면 `migrate`와 `course_id`, 예상 대상 Namespace를 명시해야 하며, 분류되지 않은 Namespace가 있으면 전환을 중단합니다.
production 기능 검증 대상은 release 실행 시 `smoke_course_namespace`로 명시하며 자동 선택하지 않습니다.

## 렌더링

```bash
kubectl kustomize deploy/overlays/dev
kubectl kustomize deploy/overlays/prod
```

## Namespace 점검

점검 명령은 Kubernetes 리소스를 변경하거나 삭제하지 않습니다.

```bash
cd generator
python namespace_reconcile.py \
  --database-url "$JCODE_DATABASE_URL" \
  --controller-namespace watcher \
  --environment prod \
  --fail-on-drift
```

DB 대신 `[{"id": 1, "code": "OS", "clss": 1}]` 형식의 JSON 파일을 `--courses-file`로 전달할 수도 있습니다.
결과는 orphan, 격리된 기존 Namespace, metadata 누락·불일치, v2 RoleBinding 누락·오류, 구형 RoleBinding 잔존, Harbor Secret 누락으로 분류됩니다.
자동 수정이나 자동 삭제 기능은 제공하지 않습니다.
