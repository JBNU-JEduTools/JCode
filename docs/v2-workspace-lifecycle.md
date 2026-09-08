# V2 Workspace 수명주기

이 문서는 Watcher와 계절학기를 제외한 V2 전환 순서와 운영 경계를 정의합니다.

## 적용 순서

1. 병합된 DNS 기준선 이미지를 dev에 적용하고 `ndots:2`, 내부 서비스 짧은 주소, Workspace DNS CIDR을 확인합니다.
2. 같은 Generator·Backend digest를 production에 적용해 기준선을 고정합니다.
3. Starter·archive PVC를 먼저 준비하고 새 Generator를 배포합니다.
4. Backend를 배포해 Flyway migration을 수행합니다. V7은 스키마와 논리 데이터만 변환하며 외부 작업을 자동 등록하지 않습니다.
5. Backend의 `k8s/assignment-path-backfill-job.yaml` 이미지를 같은 digest로 고정한 뒤 Job을 실행합니다. Production처럼 Namespace가 정리된 환경에서만 `missing-namespace=archive`를 명시합니다.
6. Job 완료 후 기존 과제의 `MIGRATE_ASSIGNMENT_PATH`와 `ARCHIVE_FINAL_SUBMISSION` operation이 모두 성공했는지 확인합니다.
7. operation 완료 후 Frontend를 배포합니다.

Backfill Job은 활성 강의의 Namespace와 course-id 소유권을 Generator에서 확인합니다. 존재하는 활성 강의만 경로 전환 작업을 등록하고, 종료 강의 또는 명시적으로 archive를 선택한 누락 Namespace의 과제는 `ARCHIVED`로 전환합니다. 같은 Job을 다시 실행해도 operation은 중복 등록되지 않습니다.

환경 프로필 → 과제 식별자 → 스타터 원본 → 삭제·보관 순서는 바꾸지 않습니다.

## 소스와 클러스터의 경계

GitHub에는 상태 모델, API 계약, migration, Generator 파일 처리, Deployment·NetworkPolicy·CronJob 원본을 둡니다. Kubernetes에는 PVC 실제 규격, StorageClass, 이미지 digest, NFS 주소, 자원 프로필 JSON, Secret을 둡니다.

필수 PVC 이름은 다음과 같습니다.

- `jcode-vol-pvc`: 학생 Workspace
- `jcode-starter-pvc`: 과제 버전별 ZIP 원본
- `jcode-archive-pvc`: 최종 작업물과 탈퇴·삭제 보관본

세 PVC는 production Generator 2개가 함께 접근하므로 `ReadWriteMany`가 필요합니다. Starter·archive PVC는 UID/GID 1000이 읽고 쓸 수 있어야 하며, 서로 다른 PVC 사이의 이동은 임시 복사 완료 후 원본을 정리합니다. 원본과 보관본이 동시에 남은 비정상 상태에서는 자동 삭제하지 않고 작업을 실패시켜 수동 확인이 가능하게 합니다.

`WORKSPACE_RESOURCE_PROFILES_JSON`은 `STANDARD`, `HIGH_MEMORY`, `GPU` 각각의 requests와 limits를 포함해야 합니다. 실제 수치는 환경별 ConfigMap에서 관리합니다.

## 상태 전이

- 과제: `PROVISIONING → ACTIVE → DELETING → ARCHIVED`, 실패 시 `PROVISION_FAILED`
- 일정: `SCHEDULED → OPEN → CLOSED → ARCHIVED`
- 가입: `PROVISIONING → READY → DELETE_PENDING → ARCHIVED`, 실패 상태에서 재시도 가능
- JCode: `PROVISIONING → READY → DELETE_PENDING → ARCHIVED`, 실패 상태에서 재시도 가능

외부 작업은 DB 상태를 먼저 기록한 뒤 `workspace_operation`이 처리합니다. 모든 Generator 요청은 같은 요청을 다시 보내도 결과가 달라지지 않아야 합니다.

## 스타터와 보관 정책

스타터 ZIP은 학생 폴더에 바로 저장하지 않습니다. `assignments/{assignmentId}/starter/v{version}.zip`에 원본을 보관하고 SHA-256을 DB에 기록합니다.

- `PRESERVE_EXISTING`: 기존 학생 파일을 유지하고 없는 파일만 추가
- `REPLACE_ALL`: 과제 폴더를 지우고 해당 버전으로 교체

마감 시 과제 폴더는 final archive로 이동해 기존 IDE의 쓰기를 차단합니다. 재개방은 final archive가 확인된 과제만 복원합니다. 삭제와 탈퇴 보관본에는 보관 만료 정보가 기록되고 CronJob이 만료된 경로만 정리합니다.

## 배포 확인

- 세 환경 프로필 생성과 Pod spec 확인
- 기존 과제 경로의 파일 유지 및 `assignment-{id}` 전환
- 선가입·후가입 학생의 동일 스타터 버전 확인
- 과제명 변경 후 Workspace 유지
- Generator 실패 후 재시도와 상태 복구
- 마감, 재개방, 과제 보관, 탈퇴·강제탈퇴
- dev에서 확인한 Generator·Backend·Frontend digest를 production에 그대로 적용

실제 PVC 용량, StorageClass, NFS endpoint, Secret과 환경별 digest는 이 저장소에 고정하지 않습니다. 배포 담당자는 위 검증을 전용 smoke 강의에서 수행하고 release manifest에 결과를 남겨야 합니다.
