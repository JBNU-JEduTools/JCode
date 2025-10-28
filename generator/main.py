import os
import time
import logging
import requests
from fastapi import FastAPI, HTTPException, Depends, status, Request
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from fastapi.responses import Response
from pydantic import BaseModel
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

# 환경 변수에서 JWT 관련 값 로드
SECRET_KEY = os.getenv("SECRET_KEY", "secret_key")
ALGORITHM = os.getenv("ALGORITHM", "alg")

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

class DeleteRequest(BaseModel):
    namespace: str
    deployment_name: str
    service_name: str

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

def create_deployment(apps_v1_api, namespace: str, deployment_name: str, app_label: str, file_path: str, student_num: str, use_vnc: bool, use_snapshot: bool) -> str:
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
    image_name = "code-server:test"

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
        base_cmd="\
            chown -R 1000:1000 /home/coder/project && \
            for i in $(seq 1 10); do mkdir -p /home/coder/project/hw$i && chown -R 1000:1000 /home/coder/project/hw$i; done && \
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
        image_name = "code-server-vnc:test"

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
                            image_pull_policy="IfNotPresent",
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

@app.post("/api/jcode")
async def deploy_resources(request: DeployRequest, token_payload: dict = Depends(verify_token)):
    try:
        load_incluster_config_or_fail()
    except Exception as e:
        logger.exception("인클러스터 구성 로딩 실패:")
        raise HTTPException(status_code=500, detail=str(e))

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
        deployment_msg = create_deployment(
            apps_v1_api,
            request.namespace,
            request.deployment_name,
            request.app_label,
            request.file_path,
            request.student_num,
            request.use_vnc,
            request.use_snapshot
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
    try:
        load_incluster_config_or_fail()
    except Exception as e:
        logger.exception("인클러스터 구성 로딩 실패:")
        raise HTTPException(status_code=500, detail=str(e))
    
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

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=5000)
