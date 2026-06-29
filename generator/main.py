import os
import re
import shlex
import stat
import time
import logging
import requests
from fastapi import FastAPI, HTTPException, Depends, status, Request, Form, File, UploadFile
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from fastapi.responses import Response
from pydantic import BaseModel, Field
from kubernetes import client, config
from kubernetes.client.rest import ApiException
from prometheus_fastapi_instrumentator import Instrumentator
import jwt

# # Prometheus client import
# from prometheus_client import Counter, Histogram, Gauge, generate_latest, CONTENT_TYPE_LATEST, CollectorRegistry, multiprocess, PlatformCollector, ProcessCollector

# # 프로세스 메트릭 등록 (CPU, Memory 등)
# ProcessCollector()   # process_cpu_seconds_total, process_resident_memory_bytes 등
# PlatformCollector()  # 플랫폼 관련 메트릭

# 로깅 설정
LOG_FILE = os.getenv("LOG_FILE", "/tmp/app.log")
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s - %(message)s",
    handlers=[
        logging.FileHandler(LOG_FILE),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

app = FastAPI()

# Instrumentator 객체 생성 및 앱에 미들웨어 적용
instrumentator = Instrumentator()
instrumentator.instrument(app).expose(app, include_in_schema=False, endpoint="/metrics")

# 환경 변수에서 JWT 관련 값 로드 (미설정 시 기동 차단)
SECRET_KEY = os.getenv("SECRET_KEY")
ALGORITHM = os.getenv("ALGORITHM")
if not SECRET_KEY or not ALGORITHM:
    raise RuntimeError("SECRET_KEY, ALGORITHM 환경 변수가 반드시 설정되어야 합니다.")

# NFS 서버 정보: 환경 변수로부터 로드
NFS_SERVER = os.getenv("NFS_SERVER", "nfs_server")
NFS_PATH = os.getenv("NFS_PATH", "nfs_path")

SNAPSHOT_NFS_SERVER = os.getenv("SNAPSHOT_NFS_SERVER", "snapshot_nfs_server")
SNAPSHOT_NFS_PATH = os.getenv("SNAPSHOT_NFS_PATH", "snapshot_nfs_path")

# 서비스 어카운트 고정 (또는 환경 변수로부터 로드)
SERVICE_ACCOUNT = os.getenv("SERVICE_ACCOUNT", "service_account")

# 요청 바디 모델 정의
class DeployRequest(BaseModel):
    namespace: str
    deployment_name: str
    service_name: str
    app_label: str
    file_path: str
    student_num: str
    use_vnc: bool
    use_snapshot: bool
    hw_count: int = Field(default=10, ge=0, le=100)
    prac_count: int = Field(default=0, ge=0, le=10)
    assignment_dirs: list[str] = Field(default=[])

class DeleteRequest(BaseModel):
    namespace: str
    deployment_name: str
    service_name: str

class NamespaceRequest(BaseModel):
    namespace: str

class ProvisionRequest(BaseModel):
    namespace: str
    dir_name: str


def validate_workspace_dir_name(dir_name: str) -> str:
    cleaned = dir_name.strip()
    if not cleaned:
        raise HTTPException(status_code=400, detail="dir_name은 비어 있을 수 없습니다.")
    if len(cleaned) > 80:
        raise HTTPException(status_code=400, detail="dir_name은 80자를 초과할 수 없습니다.")
    if os.path.isabs(cleaned) or "/" in cleaned or "\\" in cleaned:
        raise HTTPException(status_code=400, detail="dir_name에는 경로 구분자를 사용할 수 없습니다.")
    if cleaned in {".", ".."} or any(part == ".." for part in cleaned.split(os.path.sep)):
        raise HTTPException(status_code=400, detail="dir_name에는 상위 경로 참조를 사용할 수 없습니다.")
    if re.search(r'[:*?"<>|]', cleaned):
        raise HTTPException(status_code=400, detail='dir_name에는 : * ? " < > | 문자를 사용할 수 없습니다.')
    return cleaned


def validate_zip_member(info, target_dir: str):
    raw_name = info.filename
    normalized = os.path.normpath(raw_name)

    if not raw_name or normalized in {"", "."}:
        raise HTTPException(status_code=400, detail="zip 파일에 유효하지 않은 경로가 포함되어 있습니다.")
    if os.path.isabs(raw_name) or normalized.startswith("..") or f"{os.path.sep}.." in normalized:
        raise HTTPException(status_code=400, detail=f"zip 파일에 상위 경로 참조가 포함되어 있습니다: {raw_name}")

    mode = (info.external_attr >> 16) & 0o777777
    if stat.S_ISLNK(mode):
        raise HTTPException(status_code=400, detail=f"zip 파일에 symlink가 포함되어 있습니다: {raw_name}")

    target_root = os.path.realpath(target_dir)
    target_path = os.path.realpath(os.path.join(target_dir, normalized))
    if target_path != target_root and not target_path.startswith(target_root + os.sep):
        raise HTTPException(status_code=400, detail=f"zip 파일 경로가 대상 디렉토리를 벗어납니다: {raw_name}")


def safe_extract_zip(zip_file, target_dir: str):
    max_files = int(os.getenv("STARTER_ZIP_MAX_FILES", "1000"))
    max_uncompressed = int(os.getenv("STARTER_ZIP_MAX_UNCOMPRESSED_BYTES", str(200 * 1024 * 1024)))

    infos = zip_file.infolist()
    if len(infos) > max_files:
        raise HTTPException(status_code=400, detail=f"zip 파일 항목 수가 너무 많습니다: {len(infos)}")

    total_size = 0
    for info in infos:
        validate_zip_member(info, target_dir)
        total_size += info.file_size
        if total_size > max_uncompressed:
            raise HTTPException(status_code=400, detail="zip 파일 압축 해제 크기가 허용치를 초과합니다.")

    for info in infos:
        zip_file.extract(info, target_dir)

# HTTP Bearer 인증 사용
security = HTTPBearer()

def verify_token(credentials: HTTPAuthorizationCredentials = Depends(security)):
    token = credentials.credentials
    try:
        # JWT 디코드: 서명 및 유효성(만료 등) 검증
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
    except jwt.ExpiredSignatureError as e:
        logger.exception("토큰 만료 에러:")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="토큰이 만료되었습니다.",
            headers={"WWW-Authenticate": "Bearer"},
        )
    except jwt.InvalidTokenError as e:
        logger.exception("유효하지 않은 토큰 에러:")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="유효하지 않은 토큰입니다.",
            headers={"WWW-Authenticate": "Bearer"},
        )
    return payload

def load_incluster_config_or_fail():
    try:
        config.load_incluster_config()
        logger.info("인클러스터 구성 사용")
    except Exception as e:
        logger.exception("인클러스터 구성 로딩 실패:")
        raise Exception("인클러스터 구성이 불가능합니다. 이 API는 인클러스터 환경에서만 실행됩니다.")

# 기동 시 1회 인클러스터 설정 로드
load_incluster_config_or_fail()
    
# # --- Prometheus API 모니터링 메트릭 ---
# http_requests_total = Counter(
#     "http_requests_total", "Total HTTP requests",
#     ["method", "endpoint", "http_status"]
# )
# http_request_duration_seconds = Histogram(
#     "http_request_duration_seconds", "HTTP request duration in seconds",
#     ["method", "endpoint"]
# )
# inprogress_requests = Gauge(
#     "inprogress_requests", "Number of in-progress HTTP requests"
# )

# @app.middleware("http")
# async def metrics_middleware(request: Request, call_next):
#     method = request.method
#     endpoint = request.url.path
#     inprogress_requests.inc()
#     start_time = time.time()
#     try:
#         response = await call_next(request)
#     except Exception as e:
#         http_requests_total.labels(method=method, endpoint=endpoint, http_status=500).inc()
#         raise e
#     finally:
#         duration = time.time() - start_time
#         inprogress_requests.dec()
#         http_request_duration_seconds.labels(method=method, endpoint=endpoint).observe(duration)
#         http_requests_total.labels(method=method, endpoint=endpoint, http_status=response.status_code).inc()
#     return response

# # ---------------------------------

def create_deployment(apps_v1_api, namespace: str, deployment_name: str, app_label: str, file_path: str, student_num: str, use_vnc: bool, use_snapshot: bool, hw_count: int = 10, prac_count: int = 0, assignment_dirs: list = None) -> str:
    init_volume_mounts=[
        client.V1VolumeMount(
            name="jcode-vol",
            mount_path="/home/coder/.local",
            sub_path=f"extensions/{student_num}"
        )
    ]

    volume_mounts=[
        client.V1VolumeMount(
            name="jcode-vol",
            mount_path="/home/coder/.local",
            sub_path=f"extensions/{student_num}"
        ),
        client.V1VolumeMount(
            name="config-vol",
            mount_path="/home/coder/.config/code-server/config.yaml",
            sub_path="config.yaml"
        )
    ]

    volumes=[
        client.V1Volume(
            name="config-vol",
            config_map=client.V1ConfigMapVolumeSource(name="code-server-config")
        ),
        client.V1Volume(
            name="jcode-vol",
            nfs=client.V1NFSVolumeSource(
                server=NFS_SERVER,
                path=NFS_PATH
            )
        )
    ]

    # 기본 containerPort 리스트
    container_ports = [
        client.V1ContainerPort(container_port=8080)  # 기본적으로 code-server 포트만 설정
    ]

    # 기본 code-server 이미지
    image_name = os.getenv("CODE_SERVER_IMAGE", "code-server:test")

    # SNAPSHOT용 / 개발용 프로젝트 폴더 설정 구분
    if use_snapshot:
        base_cmd = "\
            chown -R 1000:1000 /home/coder/project && \
            chown -R 1000:1000 /home/coder/.local"
        init_volume_mounts.append(
            client.V1VolumeMount(
                name="snapshot-volume",
                mount_path="/home/coder/project",
                sub_path=file_path
            )
        )
        volume_mount=client.V1VolumeMount(
            name="snapshot-volume",
            mount_path="/home/coder/project",
            sub_path=file_path,
            read_only=True
        )
        volumes.append (
            client.V1Volume(
                name="snapshot-volume",
                nfs=client.V1NFSVolumeSource(
                    server=SNAPSHOT_NFS_SERVER,
                    path=SNAPSHOT_NFS_PATH
                )
            )
        )
    else:
        if assignment_dirs:
            safe_dirs = [validate_workspace_dir_name(d) for d in assignment_dirs]
            dirs = " ".join(shlex.quote(f"/home/coder/project/{d}") for d in safe_dirs)
            hw_cmd = f"mkdir -p {dirs}"
        else:
            hw_cmd = f"for i in $(seq 1 {hw_count}); do mkdir -p /home/coder/project/hw$i; done"
        prac_cmd = f" && for i in $(seq 1 {prac_count}); do mkdir -p /home/coder/project/prac$i; done" if prac_count > 0 and not assignment_dirs else ""
        base_cmd = f"\
            chown -R 1000:1000 /home/coder/project && \
            {hw_cmd}{prac_cmd} && \
            chown -R 1000:1000 /home/coder/project && \
            chown -R 1000:1000 /home/coder/.local"
        volume_mount=client.V1VolumeMount(
            name="jcode-vol",
            mount_path="/home/coder/project",
            sub_path=file_path
        )
        init_volume_mounts.append(volume_mount)

        if use_vnc:
            hook_volume_mount=client.V1VolumeMount(
                name="hook-vol",
                mount_path="/home/coder/.ipython/profile_default/startup/99-hook.py",
                sub_path="99-watcher-hook.py"
            )
            hook_volume=client.V1Volume(
                name="hook-vol",
                config_map=client.V1ConfigMapVolumeSource(name="watcher-hook-config")
            )

            volume_mounts.append(hook_volume_mount)
            volumes.append(hook_volume)

    init_command = ["sh", "-c", base_cmd]
    volume_mounts.append(volume_mount)

    # VNC를 사용할 경우 추가 설정
    if use_vnc:
        image_name = os.getenv("CODE_SERVER_VNC_IMAGE", "code-server-vnc:test")

        container_ports.append(client.V1ContainerPort(container_port=5901))  # VNC 포트 추가
        container_ports.append(client.V1ContainerPort(container_port=6080))  # noVNC 포트 추가

    deployment = client.V1Deployment(
        api_version="apps/v1",
        kind="Deployment",
        metadata=client.V1ObjectMeta(name=deployment_name, namespace=namespace, labels={"app": app_label}),
        spec=client.V1DeploymentSpec(
            replicas=1,
            selector=client.V1LabelSelector(match_labels={"app": app_label}),
            template=client.V1PodTemplateSpec(
                metadata=client.V1ObjectMeta(labels={"app": app_label}),
                spec=client.V1PodSpec(
                    service_account_name=SERVICE_ACCOUNT,
                    init_containers=[
                        client.V1Container(
                            name="fix-permissions",
                            image="busybox",
                            command=init_command,
                            volume_mounts=init_volume_mounts    # 동적으로 만든 init_volume_mounts 리스트 적용
                        )
                    ],
                    containers=[
                        client.V1Container(
                            name="code-server",
                            image=image_name,
                            image_pull_policy=os.getenv("IMAGE_PULL_POLICY", "IfNotPresent"),
                            ports=container_ports,  # 동적으로 생성된 containerPort 리스트 적용
                            env=[
                                client.V1EnvVar(name="DOCKER_USER", value="ubuntu"),
                                client.V1EnvVar(name="AUTH", value="none"),
                                client.V1EnvVar(name="DISPLAY", value=":1")  # VNC Display 설정
                            ],
                            resources=client.V1ResourceRequirements(
                                requests={"cpu": "200m", "memory": "256Mi"},
                                limits={"cpu": "4", "memory": "2Gi"}
                            ),
                            volume_mounts=volume_mounts,  # 동적으로 만든 volume_mounts 리스트 적용
                            security_context=client.V1SecurityContext(
                                run_as_user=1000,
                                run_as_group=1000
                            )
                        )
                    ],
                    volumes=volumes   # 동적으로 만든 volumes 리스트 적용
                )
            )
        )
    )
    try:
        apps_v1_api.create_namespaced_deployment(namespace=namespace, body=deployment)
        logger.info(f"Deployment '{deployment_name}' 생성 완료")
        return f"Deployment '{deployment_name}' 생성 완료"
    except ApiException as e:
        logger.exception("Deployment 생성 중 오류:")
        if e.status == 409:
            return f"Deployment '{deployment_name}'가 이미 존재합니다."
        else:
            raise Exception(f"Deployment 생성 중 오류: {e}")

def create_service(core_v1_api, namespace: str, service_name: str, app_label: str, use_vnc: bool) -> str:
    # 기본 서비스 포트 리스트
    service_ports = [
        client.V1ServicePort(name="code-server", protocol="TCP", port=8080, target_port=8080)
    ]

    # VNC를 사용할 경우 추가 설정
    if use_vnc:
        service_ports.append(client.V1ServicePort(name="vnc", protocol="TCP", port=5901, target_port=5901))
        service_ports.append(client.V1ServicePort(name="novnc", protocol="TCP", port=6080, target_port=6080))


    service = client.V1Service(
        api_version="v1",
        kind="Service",
        metadata=client.V1ObjectMeta(name=service_name, namespace=namespace),
        spec=client.V1ServiceSpec(
            selector={"app": app_label},
            ports=service_ports  # 동적으로 생성된 포트 리스트 적용
        )
    )
    try:
        core_v1_api.create_namespaced_service(namespace=namespace, body=service)
        logger.info(f"Service '{service_name}' 생성 완료")
        return f"Service '{service_name}' 생성 완료"
    except ApiException as e:
        logger.exception("Service 생성 중 오류:")
        if e.status == 409:
            return f"Service '{service_name}'가 이미 존재합니다."
        else:
            raise Exception(f"Service 생성 중 오류: {e}")
        
def delete_deployment(apps_v1_api, namespace: str, deployment_name: str) -> str:
    try :
        apps_v1_api.delete_namespaced_deployment(
            name = deployment_name,
            namespace = namespace,
            body = client.V1DeleteOptions()
        )
        logger.info(f"Deployment '{deployment_name}' 삭제 완료")
        return f"Deployment '{deployment_name}' 삭제 완료"
    except ApiException as e:
        logger.exception("Deployment 삭제 중 오류:")
        raise Exception(f"Deployment 삭제 중 오류: {str(e)}")


def delete_service(core_v1_api, namespace: str, service_name: str) -> str:
    try :
        core_v1_api.delete_namespaced_service(
            name = service_name,
            namespace = namespace,
            body = client.V1DeleteOptions()
        )
        logger.info(f"Service '{service_name}' 삭제 완료")
        return f"Service '{service_name}' 삭제 완료"
    except ApiException as e:
        logger.exception("Service 삭제 중 오류:")
        raise Exception(f"Service 삭제 중 오류: {str(e)}")
    
################ Namespace 관리 함수 ##################

ALLOWED_NS_PATTERN = re.compile(r"^jcode-[a-z0-9]+-\d+$")
PROTECTED_NAMESPACES = {"default", "kube-system", "kube-public", "kube-node-lease", "ingress-nginx", "monitoring", "watcher"}

def validate_namespace(ns: str):
    """jcode-{code}-{clss} 패턴만 허용하고, 시스템 NS 조작을 차단합니다."""
    if ns in PROTECTED_NAMESPACES:
        raise HTTPException(status_code=403, detail=f"시스템 네임스페이스 '{ns}'�� 조작할 수 없습니다.")
    if not ALLOWED_NS_PATTERN.match(ns):
        raise HTTPException(status_code=400, detail=f"네임스��이스 이름이 허용된 패턴(jcode-{{code}}-{{clss}})과 일���하지 않습니다: '{ns}'")

GENERATOR_SA_NAME = os.getenv("GENERATOR_SA_NAME", "jcode-generator")
GENERATOR_SA_NAMESPACE = os.getenv("GENERATOR_SA_NAMESPACE", "watcher")
NS_ROLE_LABEL = os.getenv("NS_ROLE_LABEL", "jcode")
WATCHER_NAMESPACE = os.getenv("WATCHER_NAMESPACE", "watcher")

def init_namespace(core_v1_api, apps_v1_api, rbac_v1_api, networking_v1_api, namespace: str):
    """jcode-init.sh와 동일한 7개 리소스를 생성하여 NS를 초기화합니다."""

    # 1. Namespace
    ns_body = client.V1Namespace(
        metadata=client.V1ObjectMeta(
            name=namespace,
            labels={"role": NS_ROLE_LABEL}
        )
    )
    try:
        core_v1_api.create_namespace(body=ns_body)
        logger.info(f"Namespace '{namespace}' 생성 완료")
    except ApiException as e:
        if e.status == 409:
            logger.info(f"Namespace '{namespace}'가 이미 존재합니다.")
        else:
            raise

    # 2. ServiceAccount
    sa_body = client.V1ServiceAccount(
        metadata=client.V1ObjectMeta(
            name="deployment-controller",
            namespace=namespace
        )
    )
    try:
        core_v1_api.create_namespaced_service_account(namespace=namespace, body=sa_body)
        logger.info(f"ServiceAccount 'deployment-controller' 생성 완료")
    except ApiException as e:
        if e.status == 409:
            logger.info(f"ServiceAccount 'deployment-controller'가 이미 존재합니다.")
        else:
            raise

    # 3. Role
    role_body = client.V1Role(
        metadata=client.V1ObjectMeta(
            name="deployment-manager",
            namespace=namespace
        ),
        rules=[
            client.V1PolicyRule(
                api_groups=["apps"],
                resources=["deployments"],
                verbs=["create", "get", "list", "watch", "update", "patch", "delete"]
            ),
            client.V1PolicyRule(
                api_groups=[""],
                resources=["services"],
                verbs=["create", "get", "list", "watch", "update", "patch", "delete"]
            ),
            client.V1PolicyRule(
                api_groups=[""],
                resources=["configmaps"],
                verbs=["get", "list", "watch"]
            ),
            client.V1PolicyRule(
                api_groups=[""],
                resources=["secrets"],
                verbs=["get", "list", "watch"]
            ),
        ]
    )
    try:
        rbac_v1_api.create_namespaced_role(namespace=namespace, body=role_body)
        logger.info(f"Role 'deployment-manager' 생성 완료")
    except ApiException as e:
        if e.status == 409:
            logger.info(f"Role 'deployment-manager'가 이미 존재합니다.")
        else:
            raise

    # 4. RoleBinding
    rb_body = client.V1RoleBinding(
        metadata=client.V1ObjectMeta(
            name="deployment-manager-binding",
            namespace=namespace
        ),
        subjects=[
            client.RbacV1Subject(
                kind="ServiceAccount",
                name=GENERATOR_SA_NAME,
                namespace=GENERATOR_SA_NAMESPACE
            )
        ],
        role_ref=client.V1RoleRef(
            kind="Role",
            name="deployment-manager",
            api_group="rbac.authorization.k8s.io"
        )
    )
    try:
        rbac_v1_api.create_namespaced_role_binding(namespace=namespace, body=rb_body)
        logger.info(f"RoleBinding 'deployment-manager-binding' 생성 완료")
    except ApiException as e:
        if e.status == 409:
            logger.info(f"RoleBinding 'deployment-manager-binding'가 이미 존재합니다.")
        else:
            raise

    # 5. ConfigMap (code-server-config)
    cm_body = client.V1ConfigMap(
        metadata=client.V1ObjectMeta(
            name="code-server-config",
            namespace=namespace
        ),
        data={
            "config.yaml": "bind-addr: 127.0.0.1:8080\nauth: none\ncert: false\n"
        }
    )
    try:
        core_v1_api.create_namespaced_config_map(namespace=namespace, body=cm_body)
        logger.info(f"ConfigMap 'code-server-config' 생성 완료")
    except ApiException as e:
        if e.status == 409:
            logger.info(f"ConfigMap 'code-server-config'가 이미 존재합니다.")
        else:
            raise

    # 6. LimitRange
    lr_body = client.V1LimitRange(
        metadata=client.V1ObjectMeta(
            name="pod-resource-limits",
            namespace=namespace
        ),
        spec=client.V1LimitRangeSpec(
            limits=[
                client.V1LimitRangeItem(
                    type="Container",
                    default_request={"cpu": "200m", "memory": "256Mi"},
                    default={"cpu": "4", "memory": "2Gi"}
                )
            ]
        )
    )
    try:
        core_v1_api.create_namespaced_limit_range(namespace=namespace, body=lr_body)
        logger.info(f"LimitRange 'pod-resource-limits' 생성 완료")
    except ApiException as e:
        if e.status == 409:
            logger.info(f"LimitRange 'pod-resource-limits'가 이미 존재합니다.")
        else:
            raise

    # 7. NetworkPolicy
    np_body = client.V1NetworkPolicy(
        metadata=client.V1ObjectMeta(
            name="watcher-networkpolicy",
            namespace=namespace
        ),
        spec=client.V1NetworkPolicySpec(
            pod_selector=client.V1LabelSelector(),
            ingress=[
                client.V1NetworkPolicyIngressRule(
                    _from=[
                        client.V1NetworkPolicyPeer(
                            namespace_selector=client.V1LabelSelector(
                                match_labels={"role": NS_ROLE_LABEL}
                            )
                        ),
                        client.V1NetworkPolicyPeer(
                            namespace_selector=client.V1LabelSelector(
                                match_labels={"kubernetes.io/metadata.name": WATCHER_NAMESPACE}
                            )
                        ),
                        client.V1NetworkPolicyPeer(
                            namespace_selector=client.V1LabelSelector(
                                match_labels={"kubernetes.io/metadata.name": "monitoring"}
                            )
                        ),
                        client.V1NetworkPolicyPeer(
                            namespace_selector=client.V1LabelSelector(
                                match_labels={"kubernetes.io/metadata.name": "ingress-nginx"}
                            )
                        ),
                    ]
                )
            ],
            policy_types=["Ingress"]
        )
    )
    try:
        networking_v1_api.create_namespaced_network_policy(namespace=namespace, body=np_body)
        logger.info(f"NetworkPolicy 'watcher-networkpolicy' 생성 완료")
    except ApiException as e:
        if e.status == 409:
            logger.info(f"NetworkPolicy 'watcher-networkpolicy'가 이미 존재합니다.")
        else:
            raise


def delete_all_resources_in_namespace(core_v1_api, apps_v1_api, namespace: str):
    """NS 내 모든 Deployment, Service, Pod를 삭제합니다 (NS 자체는 유지)."""
    # Deployment 전체 삭제
    deployments = apps_v1_api.list_namespaced_deployment(namespace=namespace)
    for dep in deployments.items:
        apps_v1_api.delete_namespaced_deployment(name=dep.metadata.name, namespace=namespace)
        logger.info(f"Deployment '{dep.metadata.name}' 삭제 완료")

    # Service 전체 삭제 (kubernetes default service 제외)
    services = core_v1_api.list_namespaced_service(namespace=namespace)
    for svc in services.items:
        if svc.metadata.name == "kubernetes":
            continue
        core_v1_api.delete_namespaced_service(name=svc.metadata.name, namespace=namespace)
        logger.info(f"Service '{svc.metadata.name}' 삭제 완료")

    # Pod 전체 삭제
    core_v1_api.delete_collection_namespaced_pod(namespace=namespace)
    logger.info(f"Namespace '{namespace}'의 모든 Pod 삭제 완료")


################ API ##################
    
# # prometheus-client 설정
# @app.get("/metrics")
# async def metrics():
#     # prometheus_client에서 기본 제공하는 메트릭들을 응답합니다.
#     try:
#         data = generate_latest()
#         return Response(content=data, media_type=CONTENT_TYPE_LATEST)
#     except Exception as e:
#         logger.exception("메트릭 생성 중 오류:")
#         raise HTTPException(status_code=500, detail="메트릭 생성 중 오류가 발생했습니다.")

@app.post("/api/namespace")
async def create_namespace_api(request: NamespaceRequest, token_payload: dict = Depends(verify_token)):
    """NS 초기화: Namespace + SA + Role + RoleBinding + ConfigMap + LimitRange + NetworkPolicy"""
    validate_namespace(request.namespace)

    core_v1_api = client.CoreV1Api()
    apps_v1_api = client.AppsV1Api()
    rbac_v1_api = client.RbacAuthorizationV1Api()
    networking_v1_api = client.NetworkingV1Api()

    try:
        init_namespace(core_v1_api, apps_v1_api, rbac_v1_api, networking_v1_api, request.namespace)
        return {"msg": f"Namespace '{request.namespace}' 초기화 완료"}
    except Exception as e:
        logger.exception("네임스페이스 초기화 중 오류:")
        raise HTTPException(status_code=500, detail=str(e))


@app.delete("/api/namespace/{ns}")
async def delete_namespace_api(ns: str, token_payload: dict = Depends(verify_token)):
    """NS 삭제: 네임스페이스와 내부 모든 리소스를 삭제합니다."""
    validate_namespace(ns)

    core_v1_api = client.CoreV1Api()

    try:
        core_v1_api.read_namespace(name=ns)
    except ApiException:
        raise HTTPException(status_code=404, detail=f"Namespace '{ns}'가 존재하지 않습니다.")

    try:
        core_v1_api.delete_namespace(name=ns)
        logger.info(f"Namespace '{ns}' 삭제 완료")
        return {"msg": f"Namespace '{ns}' 삭제 완료"}
    except Exception as e:
        logger.exception("네임스페이스 삭제 중 오류:")
        raise HTTPException(status_code=500, detail=str(e))


@app.delete("/api/namespace/{ns}/resources")
async def delete_namespace_resources_api(ns: str, token_payload: dict = Depends(verify_token)):
    """NS 내 전체 Deployment/Service/Pod 삭제 (NS 자체는 유지)."""
    validate_namespace(ns)

    core_v1_api = client.CoreV1Api()
    apps_v1_api = client.AppsV1Api()

    try:
        core_v1_api.read_namespace(name=ns)
    except ApiException:
        raise HTTPException(status_code=404, detail=f"Namespace '{ns}'가 존재하지 않습니다.")

    try:
        delete_all_resources_in_namespace(core_v1_api, apps_v1_api, ns)
        return {"msg": f"Namespace '{ns}'의 모든 리소스 삭제 완료"}
    except Exception as e:
        logger.exception("리소스 삭제 중 오류:")
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/api/jcode")
async def deploy_resources(request: DeployRequest, token_payload: dict = Depends(verify_token)):
    validate_namespace(request.namespace)

    core_v1_api = client.CoreV1Api()
    apps_v1_api = client.AppsV1Api()

    # 네임스페이스 존재 여부 확인 — 없으면 자동 생성
    try:
        core_v1_api.read_namespace(name=request.namespace)
    except ApiException:
        logger.info(f"Namespace '{request.namespace}'가 없습니다. 자동 생성합니다.")
        try:
            rbac_v1_api = client.RbacAuthorizationV1Api()
            networking_v1_api = client.NetworkingV1Api()
            init_namespace(core_v1_api, apps_v1_api, rbac_v1_api, networking_v1_api, request.namespace)
        except Exception as e:
            logger.exception("네임스페이스 자동 생성 실패:")
            raise HTTPException(status_code=500, detail=f"Namespace 자동 생성 실패: {str(e)}")

    try:
        deployment_msg = create_deployment(
            apps_v1_api,
            request.namespace,
            request.deployment_name,
            request.app_label,
            request.file_path,
            request.student_num,
            request.use_vnc,
            request.use_snapshot,
            request.hw_count,
            request.prac_count,
            request.assignment_dirs
        )
        service_msg = create_service(
            core_v1_api,
            request.namespace,
            request.service_name,
            request.app_label,
            request.use_vnc
        )

        jcodeUrl = f"http://{request.service_name}.{request.namespace}.svc.cluster.local:8080"
        msg = f"{deployment_msg}; {service_msg}"

        return {"jcodeUrl": jcodeUrl, "msg": msg}
    except Exception as e:
        logger.exception("리소스 배포 중 오류:")
        raise HTTPException(status_code=500, detail=str(e))
    
@app.delete("/api/jcode")
async def delete_resources(request: DeleteRequest, token_payload: dict = Depends(verify_token)):
    validate_namespace(request.namespace)

    core_v1_api = client.CoreV1Api()
    apps_v1_api = client.AppsV1Api()

    # 네임스페이스 존재 여부 확인
    try:
        core_v1_api.read_namespace(name=request.namespace)
    except ApiException as e:
        logger.exception("네임스페이스 조회 오류:")
        raise HTTPException(
            status_code=400,
            detail=f"Namespace '{request.namespace}'가 존재하지 않습니다. 관리자에게 문의하세요."
        )

    try:
        # 삭제 시에는 file_path, app_label 등은 사용하지 않고 이름만 사용
        deployment_msg = delete_deployment(
            apps_v1_api,
            request.namespace,
            request.deployment_name
        )
        service_msg = delete_service(
            core_v1_api,
            request.namespace,
            request.service_name
        )

        msg = f"{deployment_msg}; {service_msg}"
        return {"msg": msg}
    except Exception as e:
        logger.exception("리소스 삭제 중 오류:")
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/api/workspace/provision")
async def provision_workspace(request: ProvisionRequest, token_payload: dict = Depends(verify_token)):
    """과제 생성 시 호출: 해당 과목의 모든 학생 NFS 워크스페이스에 디렉토리 생성"""
    validate_namespace(request.namespace)
    dir_name = validate_workspace_dir_name(request.dir_name)

    nfs_mount_path = os.getenv("NFS_MOUNT_PATH", "/nfs-data")
    class_div = request.namespace.replace("jcode-", "", 1)

    base_path = os.path.join(nfs_mount_path, "workspace")
    if not os.path.isdir(base_path):
        raise HTTPException(status_code=500, detail=f"NFS workspace 경로를 찾을 수 없습니다: {base_path}")

    import glob
    student_dirs = glob.glob(os.path.join(base_path, f"{class_div}-*"))

    created = 0
    for student_dir in student_dirs:
        if not os.path.isdir(student_dir):
            continue
        hw_dir = os.path.join(student_dir, dir_name)
        os.makedirs(hw_dir, exist_ok=True)
        os.chown(hw_dir, 1000, 1000)
        created += 1

    logger.info(f"Provisioned '{dir_name}' in {created} student directories for {class_div}")
    return {"created": created, "dir_name": dir_name}


@app.post("/api/workspace/starter-code")
async def deploy_starter_code(
    namespace: str = Form(...),
    dir_name: str = Form(...),
    file: UploadFile = File(...),
    token_payload: dict = Depends(verify_token)
):
    """스타터 코드 zip 파일을 모든 학생 워크스페이스에 배포"""
    validate_namespace(namespace)
    dir_name = validate_workspace_dir_name(dir_name)

    import glob
    import zipfile
    import tempfile
    import shutil

    nfs_mount_path = os.getenv("NFS_MOUNT_PATH", "/nfs-data")
    class_div = namespace.replace("jcode-", "", 1)
    base_path = os.path.join(nfs_mount_path, "workspace")

    if not os.path.isdir(base_path):
        raise HTTPException(status_code=500, detail=f"NFS workspace 경로를 찾을 수 없습니다: {base_path}")

    content = await file.read()
    max_zip_bytes = int(os.getenv("STARTER_ZIP_MAX_BYTES", str(50 * 1024 * 1024)))
    if len(content) > max_zip_bytes:
        raise HTTPException(status_code=400, detail="zip 파일 크기가 허용치를 초과합니다.")

    # zip 파일을 임시 디렉토리에 저장
    with tempfile.NamedTemporaryFile(suffix=".zip", delete=False) as tmp:
        tmp.write(content)
        tmp_path = tmp.name

    try:
        student_dirs = glob.glob(os.path.join(base_path, f"{class_div}-*"))
        deployed = 0

        for student_dir in student_dirs:
            if not os.path.isdir(student_dir):
                continue
            target_dir = os.path.join(student_dir, dir_name)
            os.makedirs(target_dir, exist_ok=True)

            # zip 압축 해제
            with zipfile.ZipFile(tmp_path, 'r') as zf:
                safe_extract_zip(zf, target_dir)

            # 소유권 설정
            for root, dirs, files in os.walk(target_dir):
                os.chown(root, 1000, 1000)
                for f in files:
                    os.chown(os.path.join(root, f), 1000, 1000)

            deployed += 1

        logger.info(f"Deployed starter code to {deployed} directories for {class_div}/{dir_name}")
        return {"deployed": deployed, "dir_name": dir_name}
    finally:
        os.unlink(tmp_path)


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=5000)
