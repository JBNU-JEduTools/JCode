import ipaddress
import errno
import hashlib
import json
import os
import re
import shlex
import stat
import shutil
import tempfile
import time
import zipfile
import logging
import requests
from pathlib import Path
from typing import Optional
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

# Backend→Generator 전용 자격증명. 사용자 JWT와 키·audience를 공유하지 않는다.
SERVICE_SECRET = os.getenv("GENERATOR_SERVICE_SECRET")
SERVICE_ALGORITHM = os.getenv("GENERATOR_SERVICE_ALGORITHM", "HS256")
SERVICE_ISSUER = os.getenv("GENERATOR_SERVICE_ISSUER", "jcode-backend")
SERVICE_AUDIENCE = os.getenv("GENERATOR_SERVICE_AUDIENCE", "jcode-generator")
SERVICE_SUBJECT = os.getenv("GENERATOR_SERVICE_SUBJECT", "jcode-backend")
if not SERVICE_SECRET or len(SERVICE_SECRET.encode("utf-8")) < 32:
    raise RuntimeError("GENERATOR_SERVICE_SECRET은 32 byte 이상으로 설정해야 합니다.")
if SERVICE_ALGORITHM != "HS256":
    raise RuntimeError("GENERATOR_SERVICE_ALGORITHM은 HS256만 허용합니다.")

# NFS 서버 정보: 환경 변수로부터 로드
NFS_SERVER = os.getenv("NFS_SERVER", "")
NFS_PATH = os.getenv("NFS_PATH", "")
NFS_MOUNT_PATH = os.getenv("NFS_MOUNT_PATH", "/nfs-data").strip()

SNAPSHOT_NFS_SERVER = os.getenv("SNAPSHOT_NFS_SERVER", "")
SNAPSHOT_NFS_PATH = os.getenv("SNAPSHOT_NFS_PATH", "")

# 서비스 어카운트 고정 (또는 환경 변수로부터 로드)
SERVICE_ACCOUNT = os.getenv("SERVICE_ACCOUNT", "jcode-workload")

WORKSPACE_PROXY_URL = os.getenv("WORKSPACE_PROXY_URL", "").strip()
WORKSPACE_PROXY_NAMESPACE = os.getenv("WORKSPACE_PROXY_NAMESPACE", "").strip()
WORKSPACE_PROXY_POD_LABEL = os.getenv("WORKSPACE_PROXY_POD_LABEL", "").strip()
WORKSPACE_PROXY_PORT = int(os.getenv("WORKSPACE_PROXY_PORT", "3000"))
DEFAULT_HARBOR_REGISTRY = "harbor.jedutools.io"
GENERAL_WORKSPACE_SUFFIX = "의 JCode.code-workspace"
PERSONAL_WORKSPACE_LABEL = "내 작업공간"
PERSONAL_WORKSPACE_README = """# 내 작업공간

이 폴더는 과제와 별도로 자유롭게 사용하는 개인 JCode 공간입니다.

- 일반 작업은 이 폴더에 저장하세요.
- 과제 작업은 탐색기에 표시된 과제명 폴더를 사용하세요.
- JCode 실행 화면에서는 내 작업공간과 현재 열린 과제를 함께 사용할 수 있습니다.
"""
WORKSPACE_SETTINGS = {
    "chat.disableAIFeatures": True,
    "chat.commandCenter.enabled": False,
    "workbench.settings.showAISearchToggle": False,
    "extensions.autoCheckUpdates": False,
    "extensions.autoUpdate": False,
    "telemetry.telemetryLevel": "off",
}
CODE_SERVER_POLICY = {
    "AllowedExtensions": {"*": False},
    "ChatAgentMode": False,
    "ChatAgentExtensionTools": False,
    "ChatPluginsEnabled": False,
    "ChatStrictMarketplaces": True,
    "ChatMCP": "none",
    "ChatAllowedMcpServers": [],
    "ChatAllowManagedMcpServersOnly": True,
    "Claude3PIntegration": False,
    "Codex3PIntegration": False,
    "ExtensionsAutoUpdate": False,
    "EnableTelemetry": False,
    "UpdateMode": "none",
}
WORKSPACE_NO_PROXY = os.getenv(
    "WORKSPACE_NO_PROXY",
    "localhost,127.0.0.1,.svc,.cluster.local,watcher-backend-service.watcher.svc.cluster.local",
).strip()

EXTERNAL_SECRET_STORE_NAME = os.getenv("EXTERNAL_SECRET_STORE_NAME", "").strip()
EXTERNAL_SECRET_STORE_KIND = os.getenv("EXTERNAL_SECRET_STORE_KIND", "ClusterSecretStore").strip()
EXTERNAL_SECRET_REFRESH_INTERVAL = os.getenv("EXTERNAL_SECRET_REFRESH_INTERVAL", "1h").strip()
IMAGE_PULL_SECRET_READY_TIMEOUT_SECONDS = int(os.getenv("IMAGE_PULL_SECRET_READY_TIMEOUT_SECONDS", "60"))
NAMESPACE_DELETE_TIMEOUT_SECONDS = int(os.getenv("NAMESPACE_DELETE_TIMEOUT_SECONDS", "60"))
NAMESPACE_DELETE_POLL_SECONDS = float(os.getenv("NAMESPACE_DELETE_POLL_SECONDS", "2"))


def get_workspace_node_selector() -> Optional[dict[str, str]]:
    raw = os.getenv("WORKSPACE_NODE_SELECTOR", "").strip()
    if not raw:
        return None
    try:
        value = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise RuntimeError("WORKSPACE_NODE_SELECTOR는 JSON object여야 합니다.") from exc
    if not isinstance(value, dict) or not value or not all(
        isinstance(key, str) and key and isinstance(item, str) and item
        for key, item in value.items()
    ):
        raise RuntimeError("WORKSPACE_NODE_SELECTOR에는 비어 있지 않은 문자열 key/value가 필요합니다.")
    return value


def get_workspace_tolerations() -> Optional[list[client.V1Toleration]]:
    raw = os.getenv("WORKSPACE_TOLERATIONS", "").strip()
    if not raw:
        return None
    try:
        value = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise RuntimeError("WORKSPACE_TOLERATIONS는 JSON array여야 합니다.") from exc
    if not isinstance(value, list) or not all(isinstance(item, dict) for item in value):
        raise RuntimeError("WORKSPACE_TOLERATIONS는 object로 구성된 JSON array여야 합니다.")
    allowed = {"key", "operator", "value", "effect", "tolerationSeconds"}
    if any(set(item) - allowed for item in value):
        raise RuntimeError("WORKSPACE_TOLERATIONS에 허용되지 않은 필드가 있습니다.")
    return [
        client.V1Toleration(
            key=item.get("key"),
            operator=item.get("operator"),
            value=item.get("value"),
            effect=item.get("effect"),
            toleration_seconds=item.get("tolerationSeconds"),
        )
        for item in value
    ] or None


def get_pod_dns_config() -> client.V1PodDNSConfig:
    return client.V1PodDNSConfig(
        options=[client.V1PodDNSConfigOption(name="ndots", value="2")]
    )

# 요청 바디 모델 정의
class DeployRequest(BaseModel):
    course_id: int = Field(gt=0)
    namespace: str
    deployment_name: str
    service_name: str
    app_label: str
    file_path: str
    student_num: str
    use_vnc: bool
    environment_profile: str = "ALGORITHM"
    use_jupyter: bool = False
    base_image: Optional[str] = None
    resource_profile: str = "STANDARD"
    egress_policy: str = "PACKAGE_PROXY"
    workspace_scope: str = "COURSE"
    assignment_workspace_key: Optional[str] = None
    workspace_display_name: Optional[str] = Field(default=None, min_length=1, max_length=50)
    use_snapshot: bool
    hw_count: int = Field(default=0, ge=0, le=100)
    prac_count: int = Field(default=0, ge=0, le=10)
    assignment_dirs: list[str] = Field(default=[])
    assignment_labels: dict[str, str] = Field(default={})

class DeleteRequest(BaseModel):
    course_id: int = Field(gt=0)
    namespace: str
    deployment_name: str
    service_name: str

class NamespaceRequest(BaseModel):
    course_id: int = Field(gt=0)
    namespace: str
    course_name: Optional[str] = Field(default=None, min_length=1, max_length=100)
    professor_name: Optional[str] = Field(default=None, min_length=1, max_length=50)
    year: Optional[int] = Field(default=None, ge=2000, le=2100)
    term: Optional[int] = Field(default=None, ge=1, le=2)
    class_section: Optional[int] = Field(default=None, ge=1, le=999)
    use_vnc: bool = False
    environment_profile: str = "ALGORITHM"
    use_jupyter: bool = False
    base_image: Optional[str] = None
    resource_profile: str = "STANDARD"
    egress_policy: str = "PACKAGE_PROXY"
    workspace_scope: str = "COURSE"

class NamespaceMetadataRequest(BaseModel):
    course_id: int = Field(gt=0)
    course_name: str = Field(min_length=1, max_length=100)
    professor_name: str = Field(min_length=1, max_length=50)
    year: int = Field(ge=2000, le=2100)
    term: int = Field(ge=1, le=2)
    class_section: int = Field(ge=1, le=999)

class ProvisionRequest(BaseModel):
    course_id: int = Field(gt=0)
    namespace: str
    dir_name: str

class AssignmentProvisionRequest(BaseModel):
    course_id: int = Field(gt=0)
    namespace: str
    workspace_key: str
    legacy_dir_name: Optional[str] = None
    display_name: Optional[str] = Field(default=None, min_length=1, max_length=50)

class StarterDistributeRequest(BaseModel):
    course_id: int = Field(gt=0)
    namespace: str
    workspace_key: str
    artifact_key: str
    checksum: str = Field(pattern=r"^[0-9a-f]{64}$")
    overwrite_policy: str

class AssignmentArchiveRequest(BaseModel):
    course_id: int = Field(gt=0)
    namespace: str
    workspace_key: str
    display_name: Optional[str] = Field(default=None, min_length=1, max_length=50)
    retention_days: int = Field(default=90, ge=1, le=3650)
    starter_artifact_key: Optional[str] = None
    starter_checksum: Optional[str] = Field(default=None, pattern=r"^[0-9a-f]{64}$")
    starter_overwrite_policy: str = "PRESERVE_EXISTING"
    deployments: list[str] = Field(default=[])
    services: list[str] = Field(default=[])

class StudentArtifactRef(BaseModel):
    workspace_key: str
    artifact_key: str
    checksum: str = Field(pattern=r"^[0-9a-f]{64}$")
    overwrite_policy: str = "PRESERVE_EXISTING"

class StudentProvisionRequest(BaseModel):
    course_id: int = Field(gt=0)
    namespace: str
    student_num: str
    display_name: Optional[str] = Field(default=None, min_length=1, max_length=50)
    workspace_keys: list[str] = Field(default=[])
    workspace_labels: dict[str, str] = Field(default={})
    artifacts: list[StudentArtifactRef] = Field(default=[])

class StudentArchiveRequest(BaseModel):
    course_id: int = Field(gt=0)
    namespace: str
    student_num: str
    deployments: list[str] = Field(default=[])
    services: list[str] = Field(default=[])
    retention_days: int = Field(default=90, ge=1, le=3650)
    archive_key: str

class SmokeWorkspaceRequest(BaseModel):
    course_id: int = Field(gt=0)
    namespace: str
    file_path: str
    student_num: str


def parse_csv_env(name: str) -> list[str]:
    value = os.getenv(name, "")
    return [item.strip() for item in value.split(",") if item.strip()]


def get_workspace_dns_cidrs() -> list[str]:
    configured = parse_csv_env("WORKSPACE_DNS_CIDRS")
    if not configured:
        raise RuntimeError("WORKSPACE_DNS_CIDRS를 하나 이상의 CIDR로 설정해야 합니다.")

    cidrs = []
    for value in configured:
        if "/" not in value:
            raise RuntimeError(f"WORKSPACE_DNS_CIDRS에 잘못된 CIDR이 있습니다: {value}")
        try:
            cidrs.append(str(ipaddress.ip_network(value, strict=True)))
        except ValueError as exc:
            raise RuntimeError(f"WORKSPACE_DNS_CIDRS에 잘못된 CIDR이 있습니다: {value}") from exc
    return list(dict.fromkeys(cidrs))


def build_workspace_dns_peers() -> list[client.V1NetworkPolicyPeer]:
    peers = [
        client.V1NetworkPolicyPeer(
            namespace_selector=client.V1LabelSelector(
                match_labels={"kubernetes.io/metadata.name": "kube-system"}
            ),
            pod_selector=client.V1LabelSelector(
                match_labels={"k8s-app": "kube-dns"}
            ),
        )
    ]
    peers.extend(
        client.V1NetworkPolicyPeer(ip_block=client.V1IPBlock(cidr=cidr))
        for cidr in get_workspace_dns_cidrs()
    )
    return peers


def get_image_pull_secret_names() -> list[str]:
    names = parse_csv_env("IMAGE_PULL_SECRET_NAMES")
    legacy_name = os.getenv("IMAGE_PULL_SECRET_NAME", "").strip()
    if legacy_name:
        names.append(legacy_name)
    return list(dict.fromkeys(names))


def get_image_pull_secret_remote_names() -> list[str]:
    targets = get_image_pull_secret_names()
    configured = parse_csv_env("IMAGE_PULL_SECRET_REMOTE_NAMES")
    if not configured:
        return targets
    if len(configured) != len(targets):
        raise RuntimeError("IMAGE_PULL_SECRET_REMOTE_NAMES 수는 IMAGE_PULL_SECRET_NAMES와 같아야 합니다.")
    return configured


def get_workspace_proxy_env() -> list[client.V1EnvVar]:
    values = {
        "HTTP_PROXY": WORKSPACE_PROXY_URL,
        "HTTPS_PROXY": WORKSPACE_PROXY_URL,
        "http_proxy": WORKSPACE_PROXY_URL,
        "https_proxy": WORKSPACE_PROXY_URL,
        "NO_PROXY": WORKSPACE_NO_PROXY,
        "no_proxy": WORKSPACE_NO_PROXY,
    }
    return [client.V1EnvVar(name=name, value=value) for name, value in values.items()]


def get_optional_args(name: str) -> Optional[list[str]]:
    value = os.getenv(name)
    if value is None or not value.strip():
        return None
    return shlex.split(value)


def get_workspace_root() -> str:
    root = os.getenv("WORKSPACE_ROOT", "/home/coder/project").strip()
    base_path = Path("/home/coder/project")
    root_path = Path(root)
    if not root_path.is_absolute():
        raise RuntimeError("WORKSPACE_ROOT는 절대 경로여야 합니다.")
    try:
        root_path.relative_to(base_path)
    except ValueError:
        raise RuntimeError("WORKSPACE_ROOT는 /home/coder/project 하위여야 합니다.")
    return str(root_path)


def build_code_server_args(use_vnc: bool) -> list[str]:
    configured = (
        get_optional_args("CODE_SERVER_VNC_ARGS") or get_optional_args("CODE_SERVER_ARGS")
        if use_vnc
        else get_optional_args("CODE_SERVER_ARGS")
    ) or []
    if not use_vnc:
        if not any(arg == "--bind-addr" or arg.startswith("--bind-addr=") for arg in configured):
            configured[0:0] = ["--bind-addr", "0.0.0.0:8080"]
        if not any(arg == "--auth" or arg.startswith("--auth=") for arg in configured):
            configured.extend(["--auth", "none"])
    if not any(arg == "--extensions-dir" or arg.startswith("--extensions-dir=") for arg in configured):
        configured.extend(["--extensions-dir", "/home/coder/extensions"])
    if "--disable-workspace-trust" not in configured:
        configured.append("--disable-workspace-trust")
    if "--disable-telemetry" not in configured:
        configured.append("--disable-telemetry")
    if "--disable-update-check" not in configured:
        configured.append("--disable-update-check")
    if any(arg == "--restrict-workspace-root" or arg.startswith("--restrict-workspace-root=") for arg in configured):
        raise RuntimeError("현재 code-server는 --restrict-workspace-root 옵션을 지원하지 않습니다.")
    if get_workspace_root() not in configured:
        configured.append(get_workspace_root())
    return configured


def get_code_server_args(use_vnc: bool) -> Optional[list[str]]:
    # VNC image is supervised; its process receives the same arguments through an env var.
    return None if use_vnc else build_code_server_args(False)


def get_code_server_extra_env(use_vnc: bool) -> list[client.V1EnvVar]:
    workspace_root = get_workspace_root()
    watcher_namespace = "dev" if os.getenv("JCODE_ENVIRONMENT", "prod").strip() == "dev" else "watcher"
    watcher_api_base = os.getenv(
        "WATCHER_API_BASE",
        f"http://watcher-backend-service.{watcher_namespace}.svc.cluster.local:3000",
    ).strip().rstrip("/")
    if not watcher_api_base:
        raise RuntimeError("WATCHER_API_BASE를 설정해야 합니다.")
    env = [
        client.V1EnvVar(name="WORKSPACE_ROOT", value=workspace_root),
        client.V1EnvVar(name="WATCHER_API_BASE", value=watcher_api_base),
    ]
    if use_vnc:
        env.append(
            client.V1EnvVar(
                name="CODE_SERVER_EXTRA_ARGS",
                value=shlex.join(build_code_server_args(True)),
            )
        )
    return env


def get_immutable_harbor_image(name: str) -> str:
    image = os.getenv(name, "").strip()
    return validate_immutable_harbor_image(name, image)


def get_harbor_registry() -> str:
    registry = os.getenv("HARBOR_REGISTRY", DEFAULT_HARBOR_REGISTRY).strip().lower().rstrip("/")
    if not re.fullmatch(r"[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?(?::[1-9][0-9]{0,4})?", registry):
        raise RuntimeError("HARBOR_REGISTRY는 scheme과 경로 없는 registry host여야 합니다.")
    return registry


def validate_immutable_harbor_image(name: str, image: str) -> str:
    if not image:
        raise RuntimeError(f"{name}를 Harbor 이미지로 설정해야 합니다.")
    registry = get_harbor_registry()
    if not image.startswith(f"{registry}/"):
        raise RuntimeError(f"{name}는 {registry} 이미지여야 합니다: {image}")
    mutable_tag = image.endswith((":latest", ":test", ":v2", ":v2-test"))
    digest_pinned = bool(re.search(r"@sha256:[0-9a-f]{64}$", image))
    commit_tagged = bool(re.search(r":[^/@]*[0-9a-f]{7,40}(?:[-._][^/]*)?$", image))
    if mutable_tag or not (digest_pinned or commit_tagged):
        raise RuntimeError(f"{name}는 commit tag 또는 sha256 digest로 고정해야 합니다: {image}")
    return image


def get_code_server_image(use_vnc: bool) -> str:
    name = "CODE_SERVER_VNC_IMAGE" if use_vnc else "CODE_SERVER_IMAGE"
    return get_immutable_harbor_image(name)


def get_requested_workspace_image(use_vnc: bool, environment_profile: str, base_image: Optional[str]) -> str:
    if environment_profile == "CUSTOM":
        if not base_image:
            raise HTTPException(status_code=400, detail="CUSTOM 환경은 base_image가 필요합니다.")
        return validate_immutable_harbor_image("base_image", base_image)
    return get_code_server_image(use_vnc)


def validate_workspace_profile(
    environment_profile: str,
    use_vnc: bool,
    use_jupyter: bool,
    base_image: Optional[str],
    resource_profile: str,
    egress_policy: str,
    workspace_scope: str,
) -> None:
    if environment_profile not in {"ALGORITHM", "LAB", "CUSTOM"}:
        raise HTTPException(status_code=400, detail="environment_profile이 올바르지 않습니다.")
    if resource_profile not in {"STANDARD", "HIGH_MEMORY", "GPU"}:
        raise HTTPException(status_code=400, detail="resource_profile이 올바르지 않습니다.")
    if egress_policy not in {"RESTRICTED", "PACKAGE_PROXY"}:
        raise HTTPException(status_code=400, detail="egress_policy가 올바르지 않습니다.")
    if workspace_scope not in {"COURSE", "ASSIGNMENT"}:
        raise HTTPException(status_code=400, detail="workspace_scope가 올바르지 않습니다.")
    if environment_profile == "ALGORITHM" and (use_vnc or use_jupyter or base_image or resource_profile != "STANDARD"):
        raise HTTPException(status_code=409, detail="ALGORITHM 환경 설정이 표준 프로필과 일치하지 않습니다.")
    if environment_profile == "LAB" and (not use_vnc or not use_jupyter or base_image or resource_profile != "STANDARD"):
        raise HTTPException(status_code=409, detail="LAB 환경 설정이 표준 프로필과 일치하지 않습니다.")
    if environment_profile == "CUSTOM":
        get_requested_workspace_image(use_vnc, environment_profile, base_image)


def get_workspace_resources(profile: str) -> client.V1ResourceRequirements:
    raw = os.getenv("WORKSPACE_RESOURCE_PROFILES_JSON", "").strip()
    if not raw:
        raise RuntimeError("WORKSPACE_RESOURCE_PROFILES_JSON을 설정해야 합니다.")
    try:
        configured = json.loads(raw)
        value = configured[profile]
        requests_value = value["requests"]
        limits_value = value["limits"]
    except (json.JSONDecodeError, KeyError, TypeError) as error:
        raise RuntimeError(f"WORKSPACE_RESOURCE_PROFILES_JSON에 {profile} 설정이 없습니다.") from error
    if not isinstance(requests_value, dict) or not isinstance(limits_value, dict):
        raise RuntimeError(f"{profile} resource requests/limits는 JSON object여야 합니다.")
    return client.V1ResourceRequirements(requests=requests_value, limits=limits_value)


def get_workspace_init_image() -> str:
    return get_immutable_harbor_image("WORKSPACE_INIT_IMAGE")


def validate_workspace_dir_name(dir_name: str) -> str:
    cleaned = dir_name.strip()
    if not cleaned:
        raise HTTPException(status_code=400, detail="dir_name은 비어 있을 수 없습니다.")
    if len(cleaned) > 100:
        raise HTTPException(status_code=400, detail="dir_name은 100자를 초과할 수 없습니다.")
    if os.path.isabs(cleaned) or "/" in cleaned or "\\" in cleaned:
        raise HTTPException(status_code=400, detail="dir_name에는 경로 구분자를 사용할 수 없습니다.")
    if cleaned in {".", ".."} or any(part == ".." for part in cleaned.split(os.path.sep)):
        raise HTTPException(status_code=400, detail="dir_name에는 상위 경로 참조를 사용할 수 없습니다.")
    if re.search(r'[:*?"<>|]', cleaned):
        raise HTTPException(status_code=400, detail='dir_name에는 : * ? " < > | 문자를 사용할 수 없습니다.')
    return cleaned


def get_nfs_workspace_path() -> Path:
    mount_path = Path(NFS_MOUNT_PATH)
    if not mount_path.is_absolute():
        raise RuntimeError("NFS_MOUNT_PATH는 절대 경로여야 합니다.")
    return mount_path / "workspace"


def get_workspace_extensions_root() -> Path:
    directory = os.getenv("WORKSPACE_EXTENSIONS_DIR", "extensions-v2").strip()
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}", directory):
        raise RuntimeError("WORKSPACE_EXTENSIONS_DIR는 안전한 단일 디렉터리 이름이어야 합니다.")
    return Path(NFS_MOUNT_PATH) / directory


def get_workspace_extension_path(student_num: str) -> Path:
    if not re.fullmatch(r"[0-9]{1,20}", student_num):
        raise HTTPException(status_code=400, detail="student_num 형식이 올바르지 않습니다.")
    return get_workspace_extensions_root() / student_num


def get_workspace_extension_subpath(student_num: str) -> str:
    return str(get_workspace_extension_path(student_num).relative_to(Path(NFS_MOUNT_PATH)))


def prepare_workspace_extension(student_num: str) -> Path:
    validate_nfs_mount()
    path = get_workspace_extension_path(student_num)
    reject_symlink_path(path.parent, path)
    path.mkdir(parents=True, exist_ok=True)
    os.chown(path, 1000, 1000)
    return path


def get_starter_artifact_root() -> Path:
    root = Path(os.getenv("STARTER_ARTIFACT_ROOT", "/starter-data").strip())
    if not root.is_absolute():
        raise RuntimeError("STARTER_ARTIFACT_ROOT는 절대 경로여야 합니다.")
    return root


def get_workspace_archive_root() -> Path:
    root = Path(os.getenv("WORKSPACE_ARCHIVE_ROOT", "/archive-data").strip())
    if not root.is_absolute():
        raise RuntimeError("WORKSPACE_ARCHIVE_ROOT는 절대 경로여야 합니다.")
    return root


def validate_assignment_workspace_key(value: str) -> str:
    key = value.strip()
    if not re.fullmatch(r"assignment-[1-9][0-9]*", key):
        raise HTTPException(status_code=400, detail="workspace_key 형식이 올바르지 않습니다.")
    return key


def validate_starter_artifact_key(value: str, assignment_id: int, version: int) -> str:
    expected = f"assignments/{assignment_id}/starter/v{version}.zip"
    if value != expected:
        raise HTTPException(status_code=400, detail="artifact_key가 assignment/version과 일치하지 않습니다.")
    return value


def resolve_below(root: Path, relative: str) -> Path:
    root = root.resolve()
    candidate = root.joinpath(*relative.split("/")).resolve()
    try:
        candidate.relative_to(root)
    except ValueError as error:
        raise HTTPException(status_code=400, detail="저장 경로가 허용 범위를 벗어납니다.") from error
    return candidate


def verify_artifact_checksum(artifact: Path, expected: str) -> None:
    actual = hashlib.sha256(artifact.read_bytes()).hexdigest()
    if actual != expected:
        raise HTTPException(status_code=409, detail="스타터 artifact checksum이 일치하지 않습니다.")


def iter_course_student_dirs(namespace: str) -> list[Path]:
    class_div = namespace[len(COURSE_NAMESPACE_PREFIX):]
    workspace_root = get_nfs_workspace_path()
    if not workspace_root.is_dir():
        raise HTTPException(status_code=503, detail="Workspace NFS 경로를 사용할 수 없습니다.")
    return sorted(
        path for path in workspace_root.glob(f"{class_div}-*")
        if path.is_dir() and not path.is_symlink()
    )


def reject_symlink_path(root: Path, candidate: Path) -> None:
    root = root.resolve()
    current = candidate
    while current != root:
        if current.is_symlink():
            raise HTTPException(status_code=409, detail=f"관리 경로에 symlink를 사용할 수 없습니다: {candidate.name}")
        if current.parent == current:
            raise HTTPException(status_code=400, detail="관리 경로가 허용 범위를 벗어납니다.")
        current = current.parent
    try:
        candidate.resolve(strict=False).relative_to(root)
    except ValueError as error:
        raise HTTPException(status_code=400, detail="관리 경로가 허용 범위를 벗어납니다.") from error


def validate_workspace_display_name(value: str, max_length: int = 100) -> str:
    label = value.strip()
    if not label or len(label) > max_length or any(ord(character) < 32 for character in label):
        raise HTTPException(status_code=400, detail="display_name 형식이 올바르지 않습니다.")
    return label


def general_workspace_filename(display_name: str) -> str:
    label = validate_workspace_display_name(display_name, 50)
    if re.search(r'[\\/:*?"<>|]', label):
        raise HTTPException(status_code=400, detail="display_name에 파일명으로 사용할 수 없는 문자가 있습니다.")
    return f"{label}{GENERAL_WORKSPACE_SUFFIX}"


def assignment_workspace_filename(display_name: str) -> str:
    label = validate_workspace_display_name(display_name, 50)
    safe_label = re.sub(r'[\\/:*?"<>|]', "_", label).strip().strip(".")[:50]
    return f"{safe_label or '과제'}.code-workspace"


def ensure_personal_workspace_readme(personal_workspace: Path) -> None:
    readme = personal_workspace / "README.md"
    reject_symlink_path(personal_workspace, readme)
    try:
        with readme.open("x", encoding="utf-8") as output:
            output.write(PERSONAL_WORKSPACE_README)
    except FileExistsError:
        return
    os.chown(readme, 1000, 1000)
    os.chmod(readme, 0o640)


def remove_empty_legacy_workspace_dirs(student_dir: Path) -> None:
    for candidate in student_dir.iterdir():
        if candidate.is_symlink() or not re.fullmatch(r"(?:hw|prac)[1-9][0-9]*", candidate.name):
            continue
        try:
            candidate.rmdir()
        except OSError:
            # A non-empty legacy directory may contain user work and must be preserved.
            continue


def write_workspace_json(student_dir: Path, filename: str, payload: dict) -> None:
    metadata_dir = student_dir / ".jcode"
    descriptor = metadata_dir / filename
    descriptor_dir = descriptor.parent
    reject_symlink_path(student_dir, metadata_dir)
    reject_symlink_path(student_dir, descriptor_dir)
    reject_symlink_path(student_dir, descriptor)
    descriptor_dir.mkdir(parents=True, exist_ok=True)
    if not descriptor_dir.is_dir():
        raise HTTPException(status_code=409, detail="Workspace 메타데이터 경로를 사용할 수 없습니다.")
    os.chown(descriptor_dir, 1000, 1000)
    with tempfile.NamedTemporaryFile(
        mode="w",
        encoding="utf-8",
        dir=descriptor_dir,
        prefix=f".{descriptor.name}.",
        suffix=".tmp",
        delete=False,
    ) as temporary:
        json.dump(payload, temporary, ensure_ascii=False, indent=2)
        temporary.write("\n")
        temporary_path = Path(temporary.name)
    try:
        os.chown(temporary_path, 1000, 1000)
        os.chmod(temporary_path, 0o640)
        os.replace(temporary_path, descriptor)
    finally:
        temporary_path.unlink(missing_ok=True)


def read_assignment_workspace_entries(student_dir: Path) -> list[dict[str, str]]:
    metadata_dir = student_dir / ".jcode"
    if not metadata_dir.is_dir() or metadata_dir.is_symlink():
        return []
    entries = []
    descriptors = sorted(
        metadata_dir.glob("assignment-*.code-workspace"),
        key=lambda path: int(path.name.removeprefix("assignment-").removesuffix(".code-workspace"))
        if re.fullmatch(r"assignment-[1-9][0-9]*\.code-workspace", path.name)
        else 0,
    )
    for descriptor in descriptors:
        workspace_key = descriptor.name.removesuffix(".code-workspace")
        if not re.fullmatch(r"assignment-[1-9][0-9]*", workspace_key):
            continue
        if not (student_dir / workspace_key).is_dir() or descriptor.is_symlink():
            continue
        try:
            folders = json.loads(descriptor.read_text(encoding="utf-8")).get("folders", [])
            label = validate_workspace_display_name(folders[0]["name"], 50)
        except (OSError, json.JSONDecodeError, IndexError, KeyError, TypeError, HTTPException):
            continue
        entries.append({"name": label, "path": f"../{workspace_key}"})
    return entries


def remove_stale_assignment_workspace_descriptors(student_dir: Path, workspace_keys: list[str]) -> None:
    metadata_dir = student_dir / ".jcode"
    if not metadata_dir.is_dir() or metadata_dir.is_symlink():
        return
    active_keys = set(workspace_keys)
    for descriptor in metadata_dir.glob("assignment-*.code-workspace"):
        workspace_key = descriptor.name.removesuffix(".code-workspace")
        if re.fullmatch(r"assignment-[1-9][0-9]*", workspace_key) and workspace_key not in active_keys:
            reject_symlink_path(student_dir, descriptor)
            descriptor.unlink(missing_ok=True)
            remove_named_assignment_workspace_descriptor(student_dir, workspace_key)


def write_general_workspace_descriptor(student_dir: Path, display_name: Optional[str] = None) -> None:
    """Expose a personal workspace and named assignments without leaking storage keys."""
    metadata_dir = student_dir / ".jcode"
    profile = metadata_dir / "profile.json"
    if display_name is not None:
        label = validate_workspace_display_name(display_name, 50)
    else:
        try:
            label = validate_workspace_display_name(
                json.loads(profile.read_text(encoding="utf-8"))["display_name"], 50
            )
        except (OSError, json.JSONDecodeError, KeyError, TypeError, HTTPException):
            label = student_dir.name.rsplit("-", 1)[-1]

    descriptor_name = general_workspace_filename(label)
    write_workspace_json(
        student_dir,
        "profile.json",
        {"display_name": label, "general_workspace_file": descriptor_name},
    )

    personal_workspace = student_dir / "workspace"
    reject_symlink_path(student_dir, personal_workspace)
    personal_workspace.mkdir(parents=True, exist_ok=True)
    if not personal_workspace.is_dir():
        raise HTTPException(status_code=409, detail="사용자 작업공간 경로를 사용할 수 없습니다.")
    os.chown(personal_workspace, 1000, 1000)
    ensure_personal_workspace_readme(personal_workspace)
    remove_empty_legacy_workspace_dirs(student_dir)
    payload = {
        "folders": [
            {"name": PERSONAL_WORKSPACE_LABEL, "path": "../workspace"},
            *read_assignment_workspace_entries(student_dir),
        ],
        "settings": WORKSPACE_SETTINGS,
    }
    write_workspace_json(student_dir, descriptor_name, payload)
    # Keep the old path during rolling upgrades; new Backend instances open the named file.
    write_workspace_json(student_dir, "jcode.code-workspace", payload)
    for stale in metadata_dir.glob(f"*{GENERAL_WORKSPACE_SUFFIX}"):
        if stale.name != descriptor_name and not stale.is_symlink():
            stale.unlink(missing_ok=True)


def write_assignment_workspace_descriptor(student_dir: Path, workspace_key: str, display_name: Optional[str]) -> None:
    """Keep the stable directory key while showing the configured assignment name in code-server."""
    if display_name is None:
        return
    label = validate_workspace_display_name(display_name, 50)
    settings = {"settings": WORKSPACE_SETTINGS}
    write_workspace_json(student_dir, f"{workspace_key}.code-workspace", {
        "folders": [{"name": label, "path": f"../{workspace_key}"}],
        **settings,
    })
    named_dir = student_dir / ".jcode" / "assignments" / workspace_key
    named_filename = assignment_workspace_filename(label)
    write_workspace_json(student_dir, f"assignments/{workspace_key}/{named_filename}", {
        "folders": [{"name": label, "path": f"../../../{workspace_key}"}],
        **settings,
    })
    for stale in named_dir.glob("*.code-workspace"):
        if stale.name != named_filename and not stale.is_symlink():
            stale.unlink(missing_ok=True)
    write_general_workspace_descriptor(student_dir)


def remove_named_assignment_workspace_descriptor(student_dir: Path, workspace_key: str) -> None:
    named_dir = student_dir / ".jcode" / "assignments" / workspace_key
    reject_symlink_path(student_dir, named_dir)
    if named_dir.is_dir():
        for descriptor in named_dir.glob("*.code-workspace"):
            reject_symlink_path(student_dir, descriptor)
            descriptor.unlink(missing_ok=True)
        try:
            named_dir.rmdir()
            named_dir.parent.rmdir()
        except OSError:
            pass


def remove_assignment_workspace_descriptor(student_dir: Path, workspace_key: str) -> None:
    metadata_dir = student_dir / ".jcode"
    descriptor = metadata_dir / f"{workspace_key}.code-workspace"
    reject_symlink_path(student_dir, descriptor)
    descriptor.unlink(missing_ok=True)
    remove_named_assignment_workspace_descriptor(student_dir, workspace_key)
    write_general_workspace_descriptor(student_dir)


def copy_tree_preserving_existing(source: Path, target: Path) -> None:
    reject_symlink_path(target.parent, target)
    for item in source.rglob("*"):
        relative = item.relative_to(source)
        destination = target / relative
        reject_symlink_path(target, destination)
        if item.is_dir():
            destination.mkdir(parents=True, exist_ok=True)
        elif not destination.exists():
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(item, destination)


def apply_starter_artifact(artifact: Path, target: Path, overwrite_policy: str) -> None:
    if overwrite_policy not in {"PRESERVE_EXISTING", "REPLACE_ALL"}:
        raise HTTPException(status_code=400, detail="overwrite_policy가 올바르지 않습니다.")
    reject_symlink_path(target.parent, target)
    with tempfile.TemporaryDirectory() as temp_dir:
        extracted = Path(temp_dir)
        with zipfile.ZipFile(artifact, "r") as archive:
            safe_extract_zip(archive, str(extracted))
        if overwrite_policy == "REPLACE_ALL" and target.exists():
            shutil.rmtree(target)
        target.mkdir(parents=True, exist_ok=True)
        copy_tree_preserving_existing(extracted, target)
    for current, directories, files in os.walk(target):
        os.chown(current, 1000, 1000)
        for name in directories + files:
            os.chown(os.path.join(current, name), 1000, 1000)


def move_directory_safely(source: Path, destination: Path, marker: Optional[dict] = None) -> None:
    """같은 파일시스템에서는 원자적으로, 다른 PVC 사이에서는 완료 경로를 분리해 이동합니다."""
    if source.is_symlink() or destination.is_symlink():
        raise HTTPException(status_code=409, detail="보관 경로에 symlink를 사용할 수 없습니다.")
    if not source.is_dir():
        raise HTTPException(status_code=404, detail=f"이동할 경로가 없습니다: {source.name}")
    if destination.exists():
        raise HTTPException(status_code=409, detail=f"원본과 대상 경로가 함께 존재합니다: {source.name}")
    destination.parent.mkdir(parents=True, exist_ok=True)
    try:
        source.rename(destination)
    except OSError as error:
        if error.errno != errno.EXDEV:
            raise
        temporary = destination.with_name(f".{destination.name}.partial")
        if temporary.exists():
            shutil.rmtree(temporary)
        try:
            shutil.copytree(source, temporary, symlinks=True)
            if marker is not None:
                (temporary / ".retention.json").write_text(
                    json.dumps(marker, ensure_ascii=False), encoding="utf-8"
                )
            os.replace(temporary, destination)
            shutil.rmtree(source)
        finally:
            if temporary.exists():
                shutil.rmtree(temporary)
    if marker is not None:
        (destination / ".retention.json").write_text(
            json.dumps(marker, ensure_ascii=False), encoding="utf-8"
        )


def get_smoke_workspace_paths(file_path: str, student_num: str) -> tuple[Path, Path]:
    if not re.fullmatch(r"workspace/release-smoke/jcode-release-[0-9]+-smoke", file_path):
        raise HTTPException(status_code=400, detail="smoke workspace 경로 형식이 올바르지 않습니다.")
    if not re.fullmatch(r"release-smoke-[0-9]+", student_num):
        raise HTTPException(status_code=400, detail="smoke extension 경로 형식이 올바르지 않습니다.")

    nfs_root = Path(NFS_MOUNT_PATH).resolve()
    candidates = (
        nfs_root.joinpath(*file_path.split("/")),
        get_workspace_extensions_root() / student_num,
    )
    paths = []
    for candidate in candidates:
        current = candidate
        while current != nfs_root:
            if current.exists() and current.is_symlink():
                raise HTTPException(status_code=400, detail="smoke 경로에 symlink를 사용할 수 없습니다.")
            current = current.parent
        path = candidate.resolve()
        try:
            path.relative_to(nfs_root)
        except ValueError as error:
            raise HTTPException(status_code=400, detail="smoke 경로가 NFS 범위를 벗어납니다.") from error
        paths.append(path)
    return paths[0], paths[1]


def prepare_smoke_workspace(file_path: str, student_num: str) -> tuple[Path, Path]:
    validate_nfs_mount()
    paths = get_smoke_workspace_paths(file_path, student_num)
    for path in paths:
        path.mkdir(parents=True, exist_ok=True)
        os.chown(path, 1000, 1000)
    return paths


def cleanup_smoke_workspace(file_path: str, student_num: str) -> None:
    import shutil

    paths = get_smoke_workspace_paths(file_path, student_num)
    for path in paths:
        if path.exists():
            shutil.rmtree(path)
    # workspace/release-smoke는 이 기능 전용이므로 비어 있으면 정리한다.
    # 확장 공용 루트는 이 기능의 소유가 아니므로 절대 삭제하지 않는다.
    try:
        paths[0].parent.rmdir()
    except OSError:
        pass


def validate_nfs_mount() -> None:
    workspace_path = get_nfs_workspace_path()
    if not workspace_path.is_dir():
        raise RuntimeError(f"NFS workspace 경로를 찾을 수 없습니다: {workspace_path}")
    if not os.access(workspace_path, os.R_OK | os.W_OK | os.X_OK):
        raise RuntimeError(f"NFS workspace 경로에 읽기/쓰기 권한이 없습니다: {workspace_path}")


def validate_managed_storage() -> None:
    for name, path in {
        "STARTER_ARTIFACT_ROOT": get_starter_artifact_root(),
        "WORKSPACE_ARCHIVE_ROOT": get_workspace_archive_root(),
    }.items():
        if not path.is_dir():
            raise RuntimeError(f"{name} 경로를 찾을 수 없습니다: {path}")
        if not os.access(path, os.R_OK | os.W_OK | os.X_OK):
            raise RuntimeError(f"{name} 경로에 읽기/쓰기 권한이 없습니다: {path}")


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


def validate_zip_archive(zip_file, target_dir: str):
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


def safe_extract_zip(zip_file, target_dir: str):
    validate_zip_archive(zip_file, target_dir)

    for info in zip_file.infolist():
        zip_file.extract(info, target_dir)

# HTTP Bearer 인증 사용
security = HTTPBearer()

CONTROLLER_MODE = os.getenv("CONTROLLER_MODE", "").strip().lower()
if CONTROLLER_MODE not in {"bootstrap", "workspace"}:
    raise RuntimeError("CONTROLLER_MODE는 bootstrap 또는 workspace로 명시해야 합니다.")


def validate_runtime_configuration():
    if CONTROLLER_MODE == "workspace":
        required = {
            "NFS_SERVER": NFS_SERVER,
            "NFS_PATH": NFS_PATH,
            "SNAPSHOT_NFS_SERVER": SNAPSHOT_NFS_SERVER,
            "SNAPSHOT_NFS_PATH": SNAPSHOT_NFS_PATH,
            "SERVICE_ACCOUNT": SERVICE_ACCOUNT,
            "WATCHER_NAMESPACE": os.getenv("WATCHER_NAMESPACE", ""),
            "IMAGE_PULL_SECRET_NAMES": os.getenv("IMAGE_PULL_SECRET_NAMES", ""),
            "WORKSPACE_PROXY_URL": WORKSPACE_PROXY_URL,
            "WORKSPACE_PROXY_NAMESPACE": WORKSPACE_PROXY_NAMESPACE,
            "WORKSPACE_PROXY_POD_LABEL": WORKSPACE_PROXY_POD_LABEL,
        }
        missing = [name for name, value in required.items() if not str(value).strip()]
        if missing:
            raise RuntimeError(f"Generator 필수 환경값이 누락되었습니다: {', '.join(missing)}")
        get_code_server_image(False)
        get_code_server_image(True)
        get_workspace_init_image()
        build_code_server_args(False)
        build_code_server_args(True)
        for profile in ("STANDARD", "HIGH_MEMORY", "GPU"):
            get_workspace_resources(profile)
        validate_nfs_mount()
        validate_managed_storage()
    if CONTROLLER_MODE == "bootstrap":
        required = {
            "IMAGE_PULL_SECRET_NAMES": os.getenv("IMAGE_PULL_SECRET_NAMES", ""),
            "EXTERNAL_SECRET_STORE_NAME": EXTERNAL_SECRET_STORE_NAME,
            "POD_NAMESPACE": CONTROLLER_NAMESPACE,
        }
        missing = [name for name, value in required.items() if not str(value).strip()]
        if missing:
            raise RuntimeError(f"Bootstrap 필수 환경값이 누락되었습니다: {', '.join(missing)}")
        get_workspace_dns_cidrs()
        get_image_pull_secret_remote_names()


@app.on_event("startup")
def validate_on_startup():
    validate_runtime_configuration()


@app.get("/health/live", include_in_schema=False)
def health_live():
    return {"status": "UP", "controller": CONTROLLER_MODE}


@app.get("/health/ready", include_in_schema=False)
def health_ready():
    validate_runtime_configuration()
    return {"status": "READY", "controller": CONTROLLER_MODE}


def require_service_scope(required_scope: str, required_controller: str):
    """Validate a short-lived Backend service JWT and its operation scope."""
    def verify_service_token(credentials: HTTPAuthorizationCredentials = Depends(security)):
        if CONTROLLER_MODE != required_controller:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="현재 Controller가 처리하지 않는 작업입니다.",
            )
        token = credentials.credentials
        try:
            payload = jwt.decode(
                token,
                SERVICE_SECRET,
                algorithms=[SERVICE_ALGORITHM],
                audience=SERVICE_AUDIENCE,
                issuer=SERVICE_ISSUER,
                options={"require": ["exp", "iat", "iss", "aud", "sub", "scope"]},
            )
        except jwt.ExpiredSignatureError:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Generator service token이 만료되었습니다.",
                headers={"WWW-Authenticate": "Bearer"},
            )
        except jwt.InvalidTokenError:
            logger.warning("Generator service token 검증 실패")
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Generator service token이 유효하지 않습니다.",
                headers={"WWW-Authenticate": "Bearer"},
            )

        if payload.get("sub") != SERVICE_SUBJECT:
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="허용되지 않은 호출 주체입니다.")

        issued_at = int(payload["iat"])
        expires_at = int(payload["exp"])
        if expires_at - issued_at > 90:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Generator service token 수명이 너무 깁니다.")

        scopes = set(str(payload.get("scope", "")).split())
        if required_scope not in scopes:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Generator 작업 권한이 없습니다: {required_scope}",
            )
        if payload.get("namespace_prefix") != REQUEST_NAMESPACE_PREFIX:
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Namespace 소유 범위가 유효하지 않습니다.")
        return payload

    return verify_service_token


def verify_token(credentials: HTTPAuthorizationCredentials = Depends(security)):
    """Deprecated compatibility helper. New endpoints use operation-scoped service auth."""
    token = credentials.credentials
    try:
        payload = jwt.decode(
            token,
            SERVICE_SECRET,
            algorithms=[SERVICE_ALGORITHM],
            audience=SERVICE_AUDIENCE,
            issuer=SERVICE_ISSUER,
        )
    except jwt.ExpiredSignatureError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Generator service token이 만료되었습니다.",
            headers={"WWW-Authenticate": "Bearer"},
        )
    except jwt.InvalidTokenError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Generator service token이 유효하지 않습니다.",
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

def create_deployment(
    apps_v1_api, namespace: str, deployment_name: str, app_label: str,
    file_path: str, student_num: str, use_vnc: bool, use_snapshot: bool,
    hw_count: int = 0, prac_count: int = 0, assignment_dirs: list = None,
    environment_profile: str = "ALGORITHM", use_jupyter: bool = False,
    base_image: Optional[str] = None, resource_profile: str = "STANDARD",
    workspace_scope: str = "COURSE", assignment_workspace_key: Optional[str] = None,
) -> str:
    init_volume_mounts = []

    volume_mounts=[
        client.V1VolumeMount(
            name="jcode-vol",
            mount_path="/home/coder/extensions",
            sub_path=get_workspace_extension_subpath(student_num),
            read_only=True,
        ),
        client.V1VolumeMount(
            name="config-vol",
            mount_path="/home/coder/.config/code-server/config.yaml",
            sub_path="config.yaml"
        ),
        client.V1VolumeMount(
            name="config-vol",
            mount_path="/etc/vscode/policy.json",
            sub_path="policy.json",
            read_only=True,
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
        ),
        client.V1Volume(
            name="tmp-vol",
            empty_dir=client.V1EmptyDirVolumeSource(size_limit="1Gi")
        )
    ]
    volume_mounts.append(client.V1VolumeMount(name="tmp-vol", mount_path="/tmp"))

    # 기본 containerPort 리스트
    container_ports = [
        client.V1ContainerPort(container_port=8080)  # 기본적으로 code-server 포트만 설정
    ]

    # 검증된 Harbor의 불변 이미지 레퍼런스만 허용한다.
    image_name = get_requested_workspace_image(use_vnc, environment_profile, base_image)

    # SNAPSHOT용 / 개발용 프로젝트 폴더 설정 구분
    if use_snapshot:
        base_cmd = "chown -R 1000:1000 /home/coder/project"
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
        if workspace_scope == "ASSIGNMENT":
            if not assignment_workspace_key:
                raise HTTPException(status_code=400, detail="ASSIGNMENT 범위는 assignment_workspace_key가 필요합니다.")
            workspace_key = validate_assignment_workspace_key(assignment_workspace_key)
            file_path = f"{file_path.rstrip('/')}/{workspace_key}"
        if workspace_scope == "ASSIGNMENT":
            workspace_cmd = "true"
        else:
            safe_dirs = ["workspace", *[validate_workspace_dir_name(d) for d in (assignment_dirs or [])]]
            dirs = " ".join(shlex.quote(f"/home/coder/project/{d}") for d in safe_dirs)
            workspace_cmd = f"mkdir -p {dirs}"
        base_cmd = f"\
            chown -R 1000:1000 /home/coder/project && \
            {workspace_cmd} && \
            chown -R 1000:1000 /home/coder/project"
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
        container_ports.append(client.V1ContainerPort(container_port=5901))  # VNC 포트 추가
        container_ports.append(client.V1ContainerPort(container_port=6080))  # noVNC 포트 추가

    image_pull_secret_names = get_image_pull_secret_names()
    image_pull_secrets = [
        client.V1LocalObjectReference(name=name)
        for name in image_pull_secret_names
    ] or None
    code_server_args = get_code_server_args(use_vnc)
    code_server_env = [
        client.V1EnvVar(name="DOCKER_USER", value="ubuntu"),
        client.V1EnvVar(name="AUTH", value="none"),
        client.V1EnvVar(name="DISPLAY", value=":1"),  # VNC Display 설정
        client.V1EnvVar(name="JUPYTER_ENABLED", value=str(use_jupyter).lower()),
        client.V1EnvVar(name="EXTENSIONS_GALLERY", value="{}"),
    ] + get_code_server_extra_env(use_vnc) + get_workspace_proxy_env()

    deployment = client.V1Deployment(
        api_version="apps/v1",
        kind="Deployment",
        metadata=client.V1ObjectMeta(name=deployment_name, namespace=namespace, labels={"app": app_label}),
        spec=client.V1DeploymentSpec(
            replicas=1,
            progress_deadline_seconds=600,
            selector=client.V1LabelSelector(match_labels={"app": app_label}),
            template=client.V1PodTemplateSpec(
                metadata=client.V1ObjectMeta(
                    labels={"app": app_label, "jcode/component": "workspace"}
                ),
                spec=client.V1PodSpec(
                    service_account_name=SERVICE_ACCOUNT,
                    automount_service_account_token=False,
                    dns_config=get_pod_dns_config(),
                    node_selector=get_workspace_node_selector(),
                    tolerations=get_workspace_tolerations(),
                    security_context=client.V1PodSecurityContext(
                        seccomp_profile=client.V1SeccompProfile(type="RuntimeDefault")
                    ),
                    image_pull_secrets=image_pull_secrets,
                    init_containers=[
                        client.V1Container(
                            name="fix-permissions",
                            image=get_workspace_init_image(),
                            image_pull_policy=os.getenv("IMAGE_PULL_POLICY", "IfNotPresent"),
                            command=init_command,
                            volume_mounts=init_volume_mounts    # 동적으로 만든 init_volume_mounts 리스트 적용
                        )
                    ],
                    containers=[
                        client.V1Container(
                            name="code-server",
                            image=image_name,
                            image_pull_policy=os.getenv("IMAGE_PULL_POLICY", "IfNotPresent"),
                            args=code_server_args,
                            ports=container_ports,  # 동적으로 생성된 containerPort 리스트 적용
                            readiness_probe=client.V1Probe(
                                tcp_socket=client.V1TCPSocketAction(port=8080),
                                initial_delay_seconds=2,
                                period_seconds=2,
                                timeout_seconds=1,
                                failure_threshold=30,
                            ),
                            env=code_server_env,
                            resources=get_workspace_resources(resource_profile),
                            volume_mounts=volume_mounts,  # 동적으로 만든 volume_mounts 리스트 적용
                            security_context=client.V1SecurityContext(
                                run_as_user=1000,
                                run_as_group=1000,
                                allow_privilege_escalation=False,
                                capabilities=client.V1Capabilities(drop=["ALL"]),
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
        if e.status == 409:
            apps_v1_api.patch_namespaced_deployment(
                name=deployment_name,
                namespace=namespace,
                body=deployment,
            )
            logger.info(f"Deployment '{deployment_name}' 갱신 완료")
            return f"Deployment '{deployment_name}' 갱신 완료"
        else:
            logger.exception("Deployment 생성 중 오류:")
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
        if e.status == 404:
            return f"Deployment '{deployment_name}'는 이미 삭제되었습니다."
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
        if e.status == 404:
            return f"Service '{service_name}'는 이미 삭제되었습니다."
        logger.exception("Service 삭제 중 오류:")
        raise Exception(f"Service 삭제 중 오류: {str(e)}")
    
################ Namespace 관리 함수 ##################

REQUEST_NAMESPACE_PREFIX = os.getenv("REQUEST_NAMESPACE_PREFIX", "jcode-").strip()
COURSE_NAMESPACE_PREFIX = os.getenv("COURSE_NAMESPACE_PREFIX", REQUEST_NAMESPACE_PREFIX).strip()
JCODE_ENVIRONMENT = os.getenv("JCODE_ENVIRONMENT", "prod").strip()
if not re.fullmatch(r"[a-z0-9-]+-", REQUEST_NAMESPACE_PREFIX):
    raise RuntimeError("REQUEST_NAMESPACE_PREFIX 형식이 올바르지 않습니다.")
if not re.fullmatch(r"[a-z0-9-]+-", COURSE_NAMESPACE_PREFIX):
    raise RuntimeError("COURSE_NAMESPACE_PREFIX 형식이 올바르지 않습니다.")
if JCODE_ENVIRONMENT not in {"dev", "prod"}:
    raise RuntimeError("JCODE_ENVIRONMENT은 dev 또는 prod여야 합니다.")
REQUEST_NS_PATTERN = re.compile(rf"^{re.escape(REQUEST_NAMESPACE_PREFIX)}[a-z0-9]+-\d+$")
COURSE_NS_PATTERN = re.compile(rf"^{re.escape(COURSE_NAMESPACE_PREFIX)}[a-z0-9]+-\d+$")
PROTECTED_NAMESPACES = {"default", "kube-system", "kube-public", "kube-node-lease", "ingress-nginx", "monitoring", "watcher"}

def validate_namespace(ns: str):
    """현재 환경의 실제 course namespace만 허용합니다."""
    if ns in PROTECTED_NAMESPACES:
        raise HTTPException(status_code=403, detail=f"시스템 네임스페이스 '{ns}'는 조작할 수 없습니다.")
    if not COURSE_NS_PATTERN.fullmatch(ns):
        raise HTTPException(status_code=400, detail=f"현재 환경에서 허용되지 않은 Namespace입니다: '{ns}'")


def resolve_namespace(ns: str) -> str:
    """기존 Backend 요청 이름을 환경별 실제 namespace로 결정합니다."""
    if COURSE_NS_PATTERN.fullmatch(ns):
        return ns
    if COURSE_NAMESPACE_PREFIX != REQUEST_NAMESPACE_PREFIX and REQUEST_NS_PATTERN.fullmatch(ns):
        suffix = ns[len(REQUEST_NAMESPACE_PREFIX):]
        resolved = f"{COURSE_NAMESPACE_PREFIX}{suffix}"
        validate_namespace(resolved)
        return resolved
    validate_namespace(ns)
    return ns


K8S_RESOURCE_NAME_PATTERN = re.compile(r"^[a-z0-9](?:[-a-z0-9]*[a-z0-9])?$")


def validate_resource_name(name: str) -> str:
    if len(name) > 63 or not K8S_RESOURCE_NAME_PATTERN.fullmatch(name):
        raise HTTPException(status_code=400, detail="Kubernetes 리소스 이름 형식이 올바르지 않습니다.")
    return name

def ensure_course_metadata(core_v1_api, namespace: str, course_id: int):
    name = "jcode-course-metadata"
    expected = {
        "course-id": str(course_id),
        "namespace": namespace,
        "environment": JCODE_ENVIRONMENT,
    }
    try:
        existing = core_v1_api.read_namespaced_config_map(name=name, namespace=namespace)
    except ApiException as e:
        if e.status != 404:
            raise
        core_v1_api.create_namespaced_config_map(
            namespace=namespace,
            body=client.V1ConfigMap(
                metadata=client.V1ObjectMeta(
                    name=name,
                    namespace=namespace,
                    labels={"app.kubernetes.io/managed-by": "jcode-bootstrap"},
                ),
                data=expected,
                immutable=True,
            ),
        )
        return

    values = existing.data or {}
    if (
        values.get("course-id") != expected["course-id"]
        or values.get("namespace") != namespace
        or (values.get("environment") is not None and values.get("environment") != JCODE_ENVIRONMENT)
    ):
        raise HTTPException(
            status_code=409,
            detail="Namespace가 이미 다른 강의에 연결되어 있어 재초기화할 수 없습니다.",
        )


def verify_course_namespace(core_v1_api, namespace: str, course_id: int):
    try:
        metadata = core_v1_api.read_namespaced_config_map(
            name="jcode-course-metadata",
            namespace=namespace,
        )
    except ApiException as e:
        if e.status == 404:
            raise HTTPException(status_code=409, detail="Namespace가 bootstrap되지 않았습니다.")
        raise
    values = metadata.data or {}
    if (
        values.get("course-id") != str(course_id)
        or values.get("namespace") != namespace
        or (values.get("environment") is not None and values.get("environment") != JCODE_ENVIRONMENT)
    ):
        raise HTTPException(status_code=403, detail="courseId와 Namespace 소유 관계가 일치하지 않습니다.")
    namespace_object = core_v1_api.read_namespace(name=namespace)
    labels = namespace_object.metadata.labels or {}
    annotations = namespace_object.metadata.annotations or {}
    if labels.get("jcode.io/environment") != JCODE_ENVIRONMENT or annotations.get("jcode.io/environment") != JCODE_ENVIRONMENT:
        raise HTTPException(status_code=403, detail="Namespace 환경 정보가 현재 Controller와 일치하지 않습니다.")


def course_namespace_annotations(
    course_id: int,
    course_name: Optional[str] = None,
    professor_name: Optional[str] = None,
    year: Optional[int] = None,
    term: Optional[int] = None,
    class_section: Optional[int] = None,
) -> dict[str, str]:
    annotations = {
        "jcode.io/course-id": str(course_id),
        "jcode.io/environment": JCODE_ENVIRONMENT,
    }
    optional_values = {
        "jcode.io/course-name": course_name,
        "jcode.io/professor-name": professor_name,
    }
    for key, value in optional_values.items():
        if value is None:
            continue
        normalized = value.strip()
        if not normalized or re.search(r"[\x00-\x1f\x7f]", normalized):
            raise HTTPException(status_code=422, detail="강의 metadata에 사용할 수 없는 문자가 포함되어 있습니다.")
        annotations[key] = normalized
    if all(value is not None for value in (course_name, professor_name, year, term, class_section)):
        annotations["jcode.io/display-name"] = (
            f"{year}-{term} | {course_name.strip()} | {professor_name.strip()} | {class_section}분반"
        )
    return annotations


def ensure_namespace_metadata(
    core_v1_api,
    namespace: str,
    course_id: int,
    course_name: Optional[str] = None,
    professor_name: Optional[str] = None,
    year: Optional[int] = None,
    term: Optional[int] = None,
    class_section: Optional[int] = None,
):
    """기존 namespace의 강의 소유권을 확인하고 Admission용 metadata를 보완한다."""
    existing = core_v1_api.read_namespace(name=namespace)
    annotations = existing.metadata.annotations or {}
    labels = existing.metadata.labels or {}
    recorded_course_id = annotations.get("jcode.io/course-id")
    recorded_environment = annotations.get("jcode.io/environment") or labels.get("jcode.io/environment")
    if recorded_course_id and recorded_course_id != str(course_id):
        raise HTTPException(status_code=409, detail="Namespace가 이미 다른 강의에 연결되어 있습니다.")
    if recorded_environment and recorded_environment != JCODE_ENVIRONMENT:
        raise HTTPException(status_code=409, detail="Namespace가 다른 환경에 연결되어 있습니다.")
    if not recorded_course_id:
        # 구버전 namespace는 ConfigMap 소유권을 먼저 확인한 뒤 metadata를 승격한다.
        verify_course_namespace(core_v1_api, namespace, course_id)
    core_v1_api.patch_namespace(
        name=namespace,
        body={
            "metadata": {
                "labels": {
                    "role": NS_ROLE_LABEL,
                    "app.kubernetes.io/managed-by": "jcode-bootstrap",
                    "jcode.io/course-id": str(course_id),
                    "jcode.io/environment": JCODE_ENVIRONMENT,
                },
                "annotations": {
                    **course_namespace_annotations(
                        course_id, course_name, professor_name, year, term, class_section
                    ),
                },
            }
        },
    )


WORKSPACE_CONTROLLER_SA = os.getenv("WORKSPACE_CONTROLLER_SA", "jcode-workspace-v2").strip()
WORKSPACE_RUNTIME_CLUSTER_ROLE = os.getenv("WORKSPACE_RUNTIME_CLUSTER_ROLE", "jcode-workspace-runtime-v2").strip()
CONTROLLER_NAMESPACE = os.getenv("POD_NAMESPACE", "watcher").strip()
NS_ROLE_LABEL = os.getenv("NS_ROLE_LABEL", "jcode")
WATCHER_NAMESPACE = os.getenv("WATCHER_NAMESPACE", "watcher")
CONFIG_VERSION = os.getenv("JCODE_CONFIG_VERSION", "2026-08-09")


def upsert_config_map(core_v1_api, namespace: str, name: str, data: dict[str, str]):
    metadata = client.V1ObjectMeta(
        name=name,
        namespace=namespace,
        labels={"app.kubernetes.io/managed-by": "jcode-generator"},
        annotations={"jcode/config-version": CONFIG_VERSION},
    )
    body = client.V1ConfigMap(metadata=metadata, data=data)
    try:
        existing = core_v1_api.read_namespaced_config_map(name=name, namespace=namespace)
        body.metadata.resource_version = existing.metadata.resource_version
        core_v1_api.replace_namespaced_config_map(name=name, namespace=namespace, body=body)
        logger.info(f"ConfigMap '{name}' 갱신 완료")
    except ApiException as e:
        if e.status != 404:
            raise
        core_v1_api.create_namespaced_config_map(namespace=namespace, body=body)
        logger.info(f"ConfigMap '{name}' 생성 완료")


def ensure_code_server_config(core_v1_api, namespace: str):
    upsert_config_map(
        core_v1_api,
        namespace,
        "code-server-config",
        {
            "config.yaml": "bind-addr: 127.0.0.1:8080\nauth: none\ncert: false\n",
            "policy.json": json.dumps(CODE_SERVER_POLICY, ensure_ascii=False, indent=2) + "\n",
        },
    )


def ensure_watcher_hook_config(core_v1_api, namespace: str):
    hook_path = Path(os.getenv("WATCHER_HOOK_PATH", Path(__file__).with_name("watcher_hook.py")))
    upsert_config_map(
        core_v1_api,
        namespace,
        "watcher-hook-config",
        {"99-watcher-hook.py": hook_path.read_text(encoding="utf-8")},
    )


def ensure_external_image_pull_secrets(custom_objects_api, namespace: str):
    """Create ExternalSecret declarations without reading registry credentials."""
    targets = get_image_pull_secret_names()
    remotes = get_image_pull_secret_remote_names()
    for target_name, remote_name in zip(targets, remotes):
        external_secret_name = f"{target_name}-sync"
        body = {
            "apiVersion": "external-secrets.io/v1",
            "kind": "ExternalSecret",
            "metadata": {
                "name": external_secret_name,
                "namespace": namespace,
                "labels": {"app.kubernetes.io/managed-by": "jcode-generator"},
            },
            "spec": {
                "refreshInterval": EXTERNAL_SECRET_REFRESH_INTERVAL,
                "secretStoreRef": {
                    "name": EXTERNAL_SECRET_STORE_NAME,
                    "kind": EXTERNAL_SECRET_STORE_KIND,
                },
                "target": {
                    "name": target_name,
                    "creationPolicy": "Owner",
                    "template": {"type": "kubernetes.io/dockerconfigjson"},
                },
                "dataFrom": [{"extract": {"key": remote_name}}],
            },
        }
        try:
            custom_objects_api.get_namespaced_custom_object(
                group="external-secrets.io",
                version="v1",
                namespace=namespace,
                plural="externalsecrets",
                name=external_secret_name,
            )
            custom_objects_api.patch_namespaced_custom_object(
                group="external-secrets.io",
                version="v1",
                namespace=namespace,
                plural="externalsecrets",
                name=external_secret_name,
                body=body,
            )
        except ApiException as e:
            if e.status != 404:
                raise
            custom_objects_api.create_namespaced_custom_object(
                group="external-secrets.io",
                version="v1",
                namespace=namespace,
                plural="externalsecrets",
                body=body,
            )
        logger.info("ExternalSecret '%s' 적용 완료: '%s'.", external_secret_name, namespace)


def wait_for_external_image_pull_secrets(custom_objects_api, namespace: str):
    """Wait for ExternalSecret readiness without reading registry credentials."""
    secret_names = get_image_pull_secret_names()
    if not secret_names:
        raise RuntimeError("IMAGE_PULL_SECRET_NAMES는 최소 1개 이상 설정해야 합니다.")
    deadline = time.monotonic() + IMAGE_PULL_SECRET_READY_TIMEOUT_SECONDS
    pending = {f"{name}-sync" for name in secret_names}
    while pending:
        for external_secret_name in list(pending):
            try:
                external_secret = custom_objects_api.get_namespaced_custom_object(
                    group="external-secrets.io",
                    version="v1",
                    namespace=namespace,
                    plural="externalsecrets",
                    name=external_secret_name,
                )
                conditions = external_secret.get("status", {}).get("conditions", [])
                if any(
                    item.get("type") == "Ready" and str(item.get("status")).lower() == "true"
                    for item in conditions
                ):
                    pending.remove(external_secret_name)
                    logger.info("ExternalSecret '%s' 준비 완료: '%s'.", external_secret_name, namespace)
            except ApiException as e:
                if e.status != 404:
                    raise
        if pending and time.monotonic() >= deadline:
            raise RuntimeError(
                f"ExternalSecret 동기화 시간 초과: Namespace '{namespace}', resources={sorted(pending)}"
            )
        if pending:
            time.sleep(1)


def build_workspace_role_binding(namespace: str) -> client.V1RoleBinding:
    return client.V1RoleBinding(
        metadata=client.V1ObjectMeta(
            name="jcode-workspace-runtime-v2",
            namespace=namespace,
            labels={"app.kubernetes.io/managed-by": "jcode-bootstrap"},
        ),
        subjects=[
            client.RbacV1Subject(
                kind="ServiceAccount",
                name=WORKSPACE_CONTROLLER_SA,
                namespace=CONTROLLER_NAMESPACE,
            )
        ],
        role_ref=client.V1RoleRef(
            kind="ClusterRole",
            name=WORKSPACE_RUNTIME_CLUSTER_ROLE,
            api_group="rbac.authorization.k8s.io",
        ),
    )

def init_namespace(
    core_v1_api, apps_v1_api, rbac_v1_api, networking_v1_api, custom_objects_api,
    namespace: str, course_id: int, use_vnc: bool = False,
    egress_policy: str = "PACKAGE_PROXY",
    course_name: Optional[str] = None,
    professor_name: Optional[str] = None,
    year: Optional[int] = None,
    term: Optional[int] = None,
    class_section: Optional[int] = None,
):
    """고정된 namespace metadata와 runtime 권한으로 강의 공간을 초기화합니다."""

    # 1. Namespace
    ns_body = client.V1Namespace(
        metadata=client.V1ObjectMeta(
            name=namespace,
            labels={
                "role": NS_ROLE_LABEL,
                "app.kubernetes.io/managed-by": "jcode-bootstrap",
                "jcode.io/course-id": str(course_id),
                "jcode.io/environment": JCODE_ENVIRONMENT,
            },
            annotations=course_namespace_annotations(
                course_id, course_name, professor_name, year, term, class_section
            ),
        )
    )
    try:
        core_v1_api.create_namespace(body=ns_body)
        logger.info(f"Namespace '{namespace}' 생성 완료")
    except ApiException as e:
        if e.status == 409:
            logger.info(f"Namespace '{namespace}'가 이미 존재합니다.")
            ensure_namespace_metadata(
                core_v1_api, namespace, course_id,
                course_name, professor_name, year, term, class_section,
            )
        else:
            raise

    ensure_external_image_pull_secrets(custom_objects_api, namespace)

    # 2. ServiceAccount
    sa_body = client.V1ServiceAccount(
        metadata=client.V1ObjectMeta(
            name=SERVICE_ACCOUNT,
            namespace=namespace
        ),
        automount_service_account_token=False,
    )
    try:
        core_v1_api.create_namespaced_service_account(namespace=namespace, body=sa_body)
        logger.info(f"ServiceAccount '{SERVICE_ACCOUNT}' 생성 완료")
    except ApiException as e:
        if e.status == 409:
            core_v1_api.patch_namespaced_service_account(
                name=SERVICE_ACCOUNT,
                namespace=namespace,
                body=sa_body,
            )
            logger.info(f"ServiceAccount '{SERVICE_ACCOUNT}' 갱신 완료")
        else:
            raise

    # 3. RoleBinding. 권한 규칙과 대상은 요청값으로 받지 않고 고정한다.
    rb_body = build_workspace_role_binding(namespace)
    try:
        rbac_v1_api.create_namespaced_role_binding(namespace=namespace, body=rb_body)
        logger.info("RoleBinding 'jcode-workspace-runtime-v2' 생성 완료")
    except ApiException as e:
        if e.status == 409:
            rbac_v1_api.patch_namespaced_role_binding(
                name="jcode-workspace-runtime-v2",
                namespace=namespace,
                body=rb_body,
            )
            logger.info("RoleBinding 'jcode-workspace-runtime-v2' 갱신 완료")
        else:
            raise

    # 4. ConfigMap (code-server-config)
    ensure_code_server_config(core_v1_api, namespace)
    ensure_course_metadata(core_v1_api, namespace, course_id)
    if use_vnc:
        ensure_watcher_hook_config(core_v1_api, namespace)

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

    # Workspace pods may reach DNS and the Watcher API only. In particular they
    # cannot call the Generator service even though both live in the watcher NS.
    workspace_egress_rules = [
        client.V1NetworkPolicyEgressRule(
            to=build_workspace_dns_peers(),
            ports=[
                client.V1NetworkPolicyPort(port=53, protocol="UDP"),
                client.V1NetworkPolicyPort(port=53, protocol="TCP"),
            ],
        ),
        client.V1NetworkPolicyEgressRule(
            to=[
                client.V1NetworkPolicyPeer(
                    namespace_selector=client.V1LabelSelector(
                        match_labels={"kubernetes.io/metadata.name": WATCHER_NAMESPACE}
                    ),
                    pod_selector=client.V1LabelSelector(match_labels={"app": "watcher-backend"}),
                )
            ],
            ports=[client.V1NetworkPolicyPort(port=3000, protocol="TCP")],
        ),
    ]
    if egress_policy == "PACKAGE_PROXY":
        workspace_egress_rules.append(
            client.V1NetworkPolicyEgressRule(
                to=[
                    client.V1NetworkPolicyPeer(
                        namespace_selector=client.V1LabelSelector(
                            match_labels={"kubernetes.io/metadata.name": WORKSPACE_PROXY_NAMESPACE}
                        ),
                        pod_selector=client.V1LabelSelector(
                            match_labels={"app": WORKSPACE_PROXY_POD_LABEL}
                        ),
                    )
                ],
                ports=[client.V1NetworkPolicyPort(port=WORKSPACE_PROXY_PORT, protocol="TCP")],
            )
        )
    workspace_egress = client.V1NetworkPolicy(
        metadata=client.V1ObjectMeta(
            name="workspace-egress",
            namespace=namespace,
        ),
        spec=client.V1NetworkPolicySpec(
            pod_selector=client.V1LabelSelector(
                match_labels={"jcode/component": "workspace"}
            ),
            egress=workspace_egress_rules,
            policy_types=["Egress"],
        ),
    )
    try:
        networking_v1_api.create_namespaced_network_policy(
            namespace=namespace,
            body=workspace_egress,
        )
        logger.info(f"NetworkPolicy 'workspace-egress' 생성 완료")
    except ApiException as e:
        if e.status == 409:
            networking_v1_api.patch_namespaced_network_policy(
                name="workspace-egress",
                namespace=namespace,
                body=workspace_egress,
            )
            logger.info(f"NetworkPolicy 'workspace-egress' 갱신 완료")
        else:
            raise

    wait_for_external_image_pull_secrets(custom_objects_api, namespace)


def delete_all_resources_in_namespace(core_v1_api, apps_v1_api, namespace: str):
    """NS 내 Deployment·Service를 삭제한다. Pod는 owner cascade로 정리된다."""
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

    logger.info(f"Namespace '{namespace}'의 Deployment·Service 삭제 완료")


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
async def create_namespace_api(
    request: NamespaceRequest,
    token_payload: dict = Depends(require_service_scope("namespace:write", "bootstrap")),
):
    """NS 초기화: Namespace + SA + Role + RoleBinding + ConfigMap + LimitRange + NetworkPolicy"""
    namespace = resolve_namespace(request.namespace)

    core_v1_api = client.CoreV1Api()
    apps_v1_api = client.AppsV1Api()
    rbac_v1_api = client.RbacAuthorizationV1Api()
    networking_v1_api = client.NetworkingV1Api()
    custom_objects_api = client.CustomObjectsApi()

    try:
        validate_workspace_profile(
            request.environment_profile,
            request.use_vnc,
            request.use_jupyter,
            request.base_image,
            request.resource_profile,
            request.egress_policy,
            request.workspace_scope,
        )
        init_namespace(
            core_v1_api,
            apps_v1_api,
            rbac_v1_api,
            networking_v1_api,
            custom_objects_api,
            namespace,
            request.course_id,
            request.use_vnc,
            request.egress_policy,
            request.course_name,
            request.professor_name,
            request.year,
            request.term,
            request.class_section,
        )
        return {"msg": f"Namespace '{namespace}' 초기화 완료", "namespace": namespace}
    except HTTPException:
        raise
    except Exception as e:
        logger.exception("네임스페이스 초기화 중 오류:")
        raise HTTPException(status_code=500, detail=str(e))


@app.put("/api/namespace/{ns}/metadata")
async def update_namespace_metadata_api(
    ns: str,
    request: NamespaceMetadataRequest,
    token_payload: dict = Depends(require_service_scope("namespace:write", "bootstrap")),
):
    """강의 표시 metadata를 기존 Namespace에 동기화한다."""
    namespace = resolve_namespace(ns)
    try:
        ensure_namespace_metadata(
            client.CoreV1Api(), namespace, request.course_id,
            request.course_name, request.professor_name,
            request.year, request.term, request.class_section,
        )
        return {"msg": "Namespace metadata 동기화 완료", "namespace": namespace}
    except HTTPException:
        raise
    except Exception as e:
        logger.exception("네임스페이스 metadata 동기화 중 오류:")
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/namespace/{ns}")
async def get_namespace_status(
    ns: str,
    course_id: int,
    token_payload: dict = Depends(require_service_scope("namespace:read", "bootstrap")),
):
    """Backfill 전에 Namespace 존재 여부와 강의 소유권을 확인합니다."""
    namespace = resolve_namespace(ns)
    core_v1_api = client.CoreV1Api()
    try:
        core_v1_api.read_namespace(name=namespace)
    except ApiException as error:
        if error.status == 404:
            return {"exists": False, "namespace": namespace}
        raise
    verify_course_namespace(core_v1_api, namespace, course_id)
    return {"exists": True, "namespace": namespace}


def wait_for_namespace_deleted(
    core_v1_api,
    namespace: str,
    timeout_seconds: int = NAMESPACE_DELETE_TIMEOUT_SECONDS,
    poll_seconds: float = NAMESPACE_DELETE_POLL_SECONDS,
) -> bool:
    deadline = time.monotonic() + timeout_seconds
    while True:
        try:
            core_v1_api.read_namespace(name=namespace)
        except ApiException as error:
            if error.status == 404:
                return True
            raise
        if time.monotonic() >= deadline:
            return False
        time.sleep(poll_seconds)


@app.delete("/api/namespace/{ns}")
async def delete_namespace_api(
    ns: str,
    course_id: int,
    token_payload: dict = Depends(require_service_scope("namespace:delete", "bootstrap")),
):
    """NS 삭제: 네임스페이스와 내부 모든 리소스를 삭제합니다."""
    namespace = resolve_namespace(ns)

    core_v1_api = client.CoreV1Api()

    try:
        core_v1_api.read_namespace(name=namespace)
    except ApiException as e:
        if e.status == 404:
            return {"msg": f"Namespace '{namespace}'는 이미 삭제되었습니다.", "deleted": True}
        raise

    verify_course_namespace(core_v1_api, namespace, course_id)

    try:
        core_v1_api.delete_namespace(name=namespace)
        logger.info("Namespace '%s' 삭제 요청 완료", namespace)
        if not wait_for_namespace_deleted(core_v1_api, namespace):
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail=f"Namespace '{namespace}'가 아직 Terminating 상태입니다. 잠시 후 다시 시도해 주세요.",
            )
        logger.info("Namespace '%s' 실제 삭제 확인 완료", namespace)
        return {"msg": f"Namespace '{namespace}' 삭제 확인 완료", "deleted": True}
    except HTTPException:
        raise
    except Exception as e:
        logger.exception("네임스페이스 삭제 중 오류:")
        raise HTTPException(status_code=500, detail=str(e))


@app.delete("/api/namespace/{ns}/resources")
async def delete_namespace_resources_api(
    ns: str,
    course_id: int,
    token_payload: dict = Depends(require_service_scope("namespace:resources:delete", "workspace")),
):
    """NS 내 Deployment/Service 삭제 (Pod는 owner cascade, NS 자체는 유지)."""
    namespace = resolve_namespace(ns)

    core_v1_api = client.CoreV1Api()
    apps_v1_api = client.AppsV1Api()

    try:
        core_v1_api.read_namespace(name=namespace)
    except ApiException as e:
        if e.status == 404:
            return {"msg": f"Namespace '{namespace}'의 리소스는 이미 없습니다."}
        raise

    verify_course_namespace(core_v1_api, namespace, course_id)

    try:
        delete_all_resources_in_namespace(core_v1_api, apps_v1_api, namespace)
        return {"msg": f"Namespace '{namespace}'의 모든 리소스 삭제 완료"}
    except Exception as e:
        logger.exception("리소스 삭제 중 오류:")
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/api/jcode")
async def deploy_resources(
    request: DeployRequest,
    token_payload: dict = Depends(require_service_scope("jcode:write", "workspace")),
):
    namespace = resolve_namespace(request.namespace)

    core_v1_api = client.CoreV1Api()
    apps_v1_api = client.AppsV1Api()

    # Workspace Controller는 이미 bootstrap된 Namespace의 소유 메타데이터와
    # 런타임 ConfigMap만 확인한다. Cluster-scoped 리소스는 만지지 않는다.
    try:
        validate_workspace_profile(
            request.environment_profile,
            request.use_vnc,
            request.use_jupyter,
            request.base_image,
            request.resource_profile,
            request.egress_policy,
            request.workspace_scope,
        )
        verify_course_namespace(core_v1_api, namespace, request.course_id)
        prepare_workspace_extension(request.student_num)
        if not request.use_snapshot and request.workspace_scope == "COURSE":
            workspace_keys = [validate_assignment_workspace_key(value) for value in request.assignment_dirs]
            unknown_labels = set(request.assignment_labels) - set(workspace_keys)
            if unknown_labels:
                raise HTTPException(status_code=400, detail="assignment_labels에 알 수 없는 workspace_key가 있습니다.")
            class_div = namespace[len(COURSE_NAMESPACE_PREFIX):]
            workspace = get_nfs_workspace_path() / f"{class_div}-{request.student_num}"
            reject_symlink_path(workspace.parent, workspace)
            workspace.mkdir(parents=True, exist_ok=True)
            os.chown(workspace, 1000, 1000)
            for workspace_key in workspace_keys:
                assignment_path = workspace / workspace_key
                reject_symlink_path(workspace, assignment_path)
                assignment_path.mkdir(parents=True, exist_ok=True)
                os.chown(assignment_path, 1000, 1000)
                write_assignment_workspace_descriptor(
                    workspace,
                    workspace_key,
                    request.assignment_labels.get(workspace_key),
                )
            remove_stale_assignment_workspace_descriptors(workspace, workspace_keys)
            write_general_workspace_descriptor(workspace, request.workspace_display_name)
        ensure_code_server_config(core_v1_api, namespace)
        if request.use_vnc:
            ensure_watcher_hook_config(core_v1_api, namespace)
    except Exception as e:
        if isinstance(e, HTTPException):
            raise
        logger.exception("Workspace Namespace 검증·동기화 실패:")
        raise HTTPException(status_code=500, detail=f"Namespace 검증 실패: {str(e)}")

    try:
        deployment_msg = create_deployment(
            apps_v1_api,
            namespace,
            request.deployment_name,
            request.app_label,
            request.file_path,
            request.student_num,
            request.use_vnc,
            request.use_snapshot,
            request.hw_count,
            request.prac_count,
            request.assignment_dirs,
            request.environment_profile,
            request.use_jupyter,
            request.base_image,
            request.resource_profile,
            request.workspace_scope,
            request.assignment_workspace_key,
        )
        service_msg = create_service(
            core_v1_api,
            namespace,
            request.service_name,
            request.app_label,
            request.use_vnc
        )

        jcodeUrl = f"http://{request.service_name}.{namespace}.svc.cluster.local:8080"
        msg = f"{deployment_msg}; {service_msg}"

        return {"jcodeUrl": jcodeUrl, "msg": msg}
    except Exception as e:
        logger.exception("리소스 배포 중 오류:")
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/jcode/status")
async def get_jcode_status(
    course_id: int,
    namespace: str,
    deployment_name: str,
    service_name: str,
    token_payload: dict = Depends(require_service_scope("jcode:read", "workspace")),
):
    """Report readiness only after both the Deployment and Service endpoint are ready."""
    namespace = resolve_namespace(namespace)
    deployment_name = validate_resource_name(deployment_name)
    service_name = validate_resource_name(service_name)
    core_v1_api = client.CoreV1Api()
    apps_v1_api = client.AppsV1Api()
    verify_course_namespace(core_v1_api, namespace, course_id)

    try:
        deployment = apps_v1_api.read_namespaced_deployment(deployment_name, namespace)
    except ApiException as error:
        if error.status == 404:
            return {"state": "PENDING", "reasonCode": "DEPLOYMENT_PENDING"}
        raise

    conditions = deployment.status.conditions or []
    if any(
        condition.type == "Progressing"
        and condition.status == "False"
        and condition.reason == "ProgressDeadlineExceeded"
        for condition in conditions
    ):
        return {"state": "FAILED", "reasonCode": "DEPLOYMENT_PROGRESS_DEADLINE"}

    desired = deployment.spec.replicas or 1
    deployment_ready = (
        (deployment.status.observed_generation or 0) >= (deployment.metadata.generation or 0)
        and (deployment.status.updated_replicas or 0) >= desired
        and (deployment.status.available_replicas or 0) >= desired
        and (deployment.status.ready_replicas or 0) >= desired
    )
    if not deployment_ready:
        return {"state": "PENDING", "reasonCode": "DEPLOYMENT_NOT_READY"}

    try:
        endpoints = core_v1_api.read_namespaced_endpoints(service_name, namespace)
    except ApiException as error:
        if error.status == 404:
            return {"state": "PENDING", "reasonCode": "SERVICE_ENDPOINT_PENDING"}
        raise
    endpoint_ready = any(subset.addresses for subset in (endpoints.subsets or []))
    if not endpoint_ready:
        return {"state": "PENDING", "reasonCode": "SERVICE_ENDPOINT_NOT_READY"}

    return {
        "state": "READY",
        "reasonCode": "READY",
        "jcodeUrl": f"http://{service_name}.{namespace}.svc.cluster.local:8080",
    }
    
@app.delete("/api/jcode")
async def delete_resources(
    request: DeleteRequest,
    token_payload: dict = Depends(require_service_scope("jcode:delete", "workspace")),
):
    namespace = resolve_namespace(request.namespace)

    core_v1_api = client.CoreV1Api()
    apps_v1_api = client.AppsV1Api()

    # 네임스페이스 존재 여부 확인
    try:
        core_v1_api.read_namespace(name=namespace)
    except ApiException as e:
        if e.status == 404:
            return {"msg": f"Namespace '{namespace}'와 JCode 리소스는 이미 없습니다."}
        raise

    verify_course_namespace(core_v1_api, namespace, request.course_id)

    try:
        # 삭제 시에는 file_path, app_label 등은 사용하지 않고 이름만 사용
        deployment_msg = delete_deployment(
            apps_v1_api,
            namespace,
            request.deployment_name
        )
        service_msg = delete_service(
            core_v1_api,
            namespace,
            request.service_name
        )

        msg = f"{deployment_msg}; {service_msg}"
        return {"msg": msg}
    except Exception as e:
        logger.exception("리소스 삭제 중 오류:")
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/api/workspace/provision")
async def provision_workspace(
    request: ProvisionRequest,
    token_payload: dict = Depends(require_service_scope("workspace:write", "workspace")),
):
    """과제 생성 시 호출: 해당 과목의 모든 학생 NFS 워크스페이스에 디렉토리 생성"""
    namespace = resolve_namespace(request.namespace)
    verify_course_namespace(client.CoreV1Api(), namespace, request.course_id)
    dir_name = validate_workspace_dir_name(request.dir_name)

    class_div = namespace[len(COURSE_NAMESPACE_PREFIX):]

    base_path = str(get_nfs_workspace_path())
    try:
        validate_nfs_mount()
    except RuntimeError as error:
        raise HTTPException(status_code=503, detail=str(error)) from error

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


@app.post("/api/workspace/assignments/provision")
async def provision_assignment_workspace(
    request: AssignmentProvisionRequest,
    token_payload: dict = Depends(require_service_scope("workspace:write", "workspace")),
):
    """불변 assignment key를 모든 기존 학생 공간에 멱등하게 준비합니다."""
    namespace = resolve_namespace(request.namespace)
    verify_course_namespace(client.CoreV1Api(), namespace, request.course_id)
    workspace_key = validate_assignment_workspace_key(request.workspace_key)
    legacy = validate_workspace_dir_name(request.legacy_dir_name) if request.legacy_dir_name else None
    migrated = 0
    created = 0
    for student_dir in iter_course_student_dirs(namespace):
        target = student_dir / workspace_key
        source = student_dir / legacy if legacy and legacy != workspace_key else None
        reject_symlink_path(student_dir, target)
        if source is not None:
            reject_symlink_path(student_dir, source)
        if target.exists():
            if source and source.exists():
                raise HTTPException(
                    status_code=409,
                    detail=f"기존 경로와 새 경로가 함께 존재합니다: {student_dir.name}",
                )
        else:
            if source and source.exists():
                source.rename(target)
                migrated += 1
            else:
                target.mkdir(parents=True, exist_ok=True)
                created += 1
        os.chown(target, 1000, 1000)
        write_assignment_workspace_descriptor(student_dir, workspace_key, request.display_name)
    return {"workspace_key": workspace_key, "migrated": migrated, "created": created}


@app.post("/api/workspace/assignments/starter/upload")
async def upload_starter_artifact(
    course_id: int = Form(...),
    namespace: str = Form(...),
    assignment_id: int = Form(...),
    version: int = Form(...),
    artifact_key: str = Form(...),
    file: UploadFile = File(...),
    token_payload: dict = Depends(require_service_scope("workspace:write", "workspace")),
):
    """스타터 ZIP 원본을 학생 공간과 분리된 보관소에 저장합니다."""
    namespace = resolve_namespace(namespace)
    verify_course_namespace(client.CoreV1Api(), namespace, course_id)
    if assignment_id <= 0 or version <= 0:
        raise HTTPException(status_code=400, detail="assignment_id와 version은 양수여야 합니다.")
    key = validate_starter_artifact_key(artifact_key, assignment_id, version)
    root = get_starter_artifact_root()
    root.mkdir(parents=True, exist_ok=True)
    target = resolve_below(root, key)
    content = await file.read()
    max_bytes = int(os.getenv("STARTER_ZIP_MAX_BYTES", str(50 * 1024 * 1024)))
    if not content or len(content) > max_bytes:
        raise HTTPException(status_code=400, detail="zip 파일 크기가 허용 범위를 벗어납니다.")
    checksum = hashlib.sha256(content).hexdigest()
    if target.exists():
        existing = hashlib.sha256(target.read_bytes()).hexdigest()
        if existing != checksum:
            raise HTTPException(status_code=409, detail="같은 artifact_key에 다른 파일이 이미 있습니다.")
        return {"artifact_key": key, "checksum": checksum, "size_bytes": target.stat().st_size}
    target.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile(dir=target.parent, suffix=".upload", delete=False) as temporary:
        temporary.write(content)
        temporary_path = Path(temporary.name)
    try:
        with zipfile.ZipFile(temporary_path, "r") as archive:
            validate_zip_archive(archive, str(target.parent))
        os.replace(temporary_path, target)
        os.chmod(target, 0o440)
    finally:
        temporary_path.unlink(missing_ok=True)
    return {"artifact_key": key, "checksum": checksum, "size_bytes": len(content)}


@app.post("/api/workspace/assignments/starter/distribute")
async def distribute_starter_artifact(
    request: StarterDistributeRequest,
    token_payload: dict = Depends(require_service_scope("workspace:write", "workspace")),
):
    namespace = resolve_namespace(request.namespace)
    verify_course_namespace(client.CoreV1Api(), namespace, request.course_id)
    workspace_key = validate_assignment_workspace_key(request.workspace_key)
    if not re.fullmatch(r"assignments/[1-9][0-9]*/starter/v[1-9][0-9]*\.zip", request.artifact_key):
        raise HTTPException(status_code=400, detail="artifact_key 형식이 올바르지 않습니다.")
    artifact = resolve_below(get_starter_artifact_root(), request.artifact_key)
    if not artifact.is_file():
        raise HTTPException(status_code=404, detail="스타터 artifact를 찾을 수 없습니다.")
    verify_artifact_checksum(artifact, request.checksum)
    deployed = 0
    for student_dir in iter_course_student_dirs(namespace):
        apply_starter_artifact(artifact, student_dir / workspace_key, request.overwrite_policy)
        deployed += 1
    return {"workspace_key": workspace_key, "deployed": deployed}


@app.post("/api/workspace/assignments/archive")
async def archive_assignment_workspace(
    request: AssignmentArchiveRequest,
    token_payload: dict = Depends(require_service_scope("workspace:write", "workspace")),
):
    namespace = resolve_namespace(request.namespace)
    verify_course_namespace(client.CoreV1Api(), namespace, request.course_id)
    apps_api = client.AppsV1Api()
    core_api = client.CoreV1Api()
    for name in request.deployments:
        delete_deployment(apps_api, namespace, name)
    for name in request.services:
        delete_service(core_api, namespace, name)
    workspace_key = validate_assignment_workspace_key(request.workspace_key)
    archive_root = get_workspace_archive_root()
    archive_root.mkdir(parents=True, exist_ok=True)
    class_div = namespace[len(COURSE_NAMESPACE_PREFIX):]
    archived = 0
    for student_dir in iter_course_student_dirs(namespace):
        source = student_dir / workspace_key
        final_source = resolve_below(
            archive_root, f"final/{class_div}/{student_dir.name}/{workspace_key}"
        )
        if not source.exists() and final_source.exists():
            source = final_source
        destination = resolve_below(archive_root, f"{class_div}/{student_dir.name}/{workspace_key}")
        if not source.exists():
            remove_assignment_workspace_descriptor(student_dir, workspace_key)
            continue
        if destination.exists():
            raise HTTPException(status_code=409, detail=f"보관 경로가 이미 존재합니다: {student_dir.name}")
        move_directory_safely(
            source,
            destination,
            {
                "course_id": request.course_id,
                "workspace_key": workspace_key,
                "retention_days": request.retention_days,
                "archived_at": int(time.time()),
            },
        )
        remove_assignment_workspace_descriptor(student_dir, workspace_key)
        archived += 1
    return {"workspace_key": workspace_key, "archived": archived}


def move_assignment_between_workspace_and_final_archive(
    namespace: str,
    workspace_key: str,
    retention_days: int,
    restore: bool,
    starter_artifact: Optional[Path] = None,
    starter_overwrite_policy: str = "PRESERVE_EXISTING",
    display_name: Optional[str] = None,
) -> int:
    class_div = namespace[len(COURSE_NAMESPACE_PREFIX):]
    archive_root = get_workspace_archive_root()
    moved = 0
    for student_dir in iter_course_student_dirs(namespace):
        workspace_path = student_dir / workspace_key
        final_path = resolve_below(archive_root, f"final/{class_div}/{student_dir.name}/{workspace_key}")
        source, destination = (final_path, workspace_path) if restore else (workspace_path, final_path)
        if not source.exists():
            if destination.exists():
                if restore:
                    write_assignment_workspace_descriptor(student_dir, workspace_key, display_name)
                else:
                    remove_assignment_workspace_descriptor(student_dir, workspace_key)
                continue
            if restore:
                destination.mkdir(parents=True, exist_ok=True)
                os.chown(destination, 1000, 1000)
                if starter_artifact is not None:
                    apply_starter_artifact(starter_artifact, destination, starter_overwrite_policy)
                write_assignment_workspace_descriptor(student_dir, workspace_key, display_name)
                moved += 1
            continue
        if destination.exists():
            raise HTTPException(status_code=409, detail=f"원본과 대상 경로가 함께 존재합니다: {student_dir.name}")
        if restore:
            move_directory_safely(source, destination)
            (destination / ".retention.json").unlink(missing_ok=True)
        else:
            move_directory_safely(
                source,
                destination,
                {
                    "workspace_key": workspace_key,
                    "retention_days": retention_days,
                    "archived_at": int(time.time()),
                },
            )
        if restore:
            write_assignment_workspace_descriptor(student_dir, workspace_key, display_name)
        else:
            remove_assignment_workspace_descriptor(student_dir, workspace_key)
        moved += 1
    return moved


@app.post("/api/workspace/assignments/finalize")
async def finalize_assignment_workspace(
    request: AssignmentArchiveRequest,
    token_payload: dict = Depends(require_service_scope("workspace:write", "workspace")),
):
    namespace = resolve_namespace(request.namespace)
    verify_course_namespace(client.CoreV1Api(), namespace, request.course_id)
    apps_api = client.AppsV1Api()
    core_api = client.CoreV1Api()
    for name in request.deployments:
        delete_deployment(apps_api, namespace, name)
    for name in request.services:
        delete_service(core_api, namespace, name)
    workspace_key = validate_assignment_workspace_key(request.workspace_key)
    moved = move_assignment_between_workspace_and_final_archive(
        namespace, workspace_key, request.retention_days, restore=False
    )
    return {"finalized": True, "workspace_key": workspace_key, "moved": moved}


@app.post("/api/workspace/assignments/restore")
async def restore_assignment_workspace(
    request: AssignmentArchiveRequest,
    token_payload: dict = Depends(require_service_scope("workspace:write", "workspace")),
):
    namespace = resolve_namespace(request.namespace)
    verify_course_namespace(client.CoreV1Api(), namespace, request.course_id)
    workspace_key = validate_assignment_workspace_key(request.workspace_key)
    starter_artifact = None
    if request.starter_artifact_key or request.starter_checksum:
        if not request.starter_artifact_key or not request.starter_checksum:
            raise HTTPException(status_code=400, detail="스타터 artifact key와 checksum을 함께 보내야 합니다.")
        if not re.fullmatch(r"assignments/[1-9][0-9]*/starter/v[1-9][0-9]*\.zip", request.starter_artifact_key):
            raise HTTPException(status_code=400, detail="artifact_key 형식이 올바르지 않습니다.")
        starter_artifact = resolve_below(get_starter_artifact_root(), request.starter_artifact_key)
        if not starter_artifact.is_file():
            raise HTTPException(status_code=404, detail="스타터 artifact를 찾을 수 없습니다.")
        verify_artifact_checksum(starter_artifact, request.starter_checksum)
    moved = move_assignment_between_workspace_and_final_archive(
        namespace,
        workspace_key,
        request.retention_days,
        restore=True,
        starter_artifact=starter_artifact,
        starter_overwrite_policy=request.starter_overwrite_policy,
        display_name=request.display_name,
    )
    return {"restored": True, "workspace_key": workspace_key, "moved": moved}


@app.post("/api/workspace/students/provision")
async def provision_student_workspace(
    request: StudentProvisionRequest,
    token_payload: dict = Depends(require_service_scope("workspace:write", "workspace")),
):
    namespace = resolve_namespace(request.namespace)
    verify_course_namespace(client.CoreV1Api(), namespace, request.course_id)
    workspace_keys = [validate_assignment_workspace_key(value) for value in request.workspace_keys]
    unknown_labels = set(request.workspace_labels) - set(workspace_keys)
    if unknown_labels:
        raise HTTPException(status_code=400, detail="workspace_labels에 알 수 없는 workspace_key가 있습니다.")
    class_div = namespace[len(COURSE_NAMESPACE_PREFIX):]
    workspace = get_nfs_workspace_path() / f"{class_div}-{request.student_num}"
    prepare_workspace_extension(request.student_num)
    reject_symlink_path(workspace.parent, workspace)
    workspace.mkdir(parents=True, exist_ok=True)
    os.chown(workspace, 1000, 1000)
    for workspace_key in workspace_keys:
        assignment_path = workspace / workspace_key
        reject_symlink_path(workspace, assignment_path)
        assignment_path.mkdir(parents=True, exist_ok=True)
        os.chown(assignment_path, 1000, 1000)
        write_assignment_workspace_descriptor(workspace, workspace_key, request.workspace_labels.get(workspace_key))
    remove_stale_assignment_workspace_descriptors(workspace, workspace_keys)
    applied = 0
    for artifact_ref in request.artifacts:
        workspace_key = validate_assignment_workspace_key(artifact_ref.workspace_key)
        if not re.fullmatch(r"assignments/[1-9][0-9]*/starter/v[1-9][0-9]*\.zip", artifact_ref.artifact_key):
            raise HTTPException(status_code=400, detail="artifact_key 형식이 올바르지 않습니다.")
        artifact = resolve_below(get_starter_artifact_root(), artifact_ref.artifact_key)
        if not artifact.is_file():
            raise HTTPException(status_code=404, detail=f"스타터 artifact를 찾을 수 없습니다: {artifact_ref.artifact_key}")
        verify_artifact_checksum(artifact, artifact_ref.checksum)
        apply_starter_artifact(artifact, workspace / workspace_key, artifact_ref.overwrite_policy)
        applied += 1
    write_general_workspace_descriptor(workspace, request.display_name)
    return {"ready": True, "workspace": workspace.name, "starter_artifacts": applied}


@app.post("/api/workspace/students/archive")
async def archive_student_workspace(
    request: StudentArchiveRequest,
    token_payload: dict = Depends(require_service_scope("workspace:write", "workspace")),
):
    namespace = resolve_namespace(request.namespace)
    if not re.fullmatch(r"[0-9]{1,20}", request.student_num):
        raise HTTPException(status_code=400, detail="student_num 형식이 올바르지 않습니다.")
    if not re.fullmatch(r"[0-9a-f-]{36}", request.archive_key):
        raise HTTPException(status_code=400, detail="archive_key 형식이 올바르지 않습니다.")

    class_div = namespace[len(COURSE_NAMESPACE_PREFIX):]
    source = get_nfs_workspace_path() / f"{class_div}-{request.student_num}"
    destination = resolve_below(
        get_workspace_archive_root(),
        f"memberships/{class_div}/{request.student_num}/{request.archive_key}",
    )
    core_api = client.CoreV1Api()
    try:
        existing_namespace = core_api.read_namespace(name=namespace)
        namespace_exists = True
    except ApiException as error:
        if error.status != 404:
            raise
        namespace_exists = False

    if namespace_exists:
        annotations = existing_namespace.metadata.annotations or {}
        labels = existing_namespace.metadata.labels or {}
        recorded_course_id = annotations.get("jcode.io/course-id") or labels.get("jcode.io/course-id")
        if recorded_course_id and recorded_course_id != str(request.course_id):
            if source.exists():
                raise HTTPException(
                    status_code=409,
                    detail="Namespace가 다른 강의에 재사용되었고 동일한 Workspace 경로가 존재합니다.",
                )
            return {
                "archived": True,
                "archive_key": request.archive_key,
                "namespace_reused": True,
            }
        verify_course_namespace(core_api, namespace, request.course_id)
        apps_api = client.AppsV1Api()
        for name in request.deployments:
            delete_deployment(apps_api, namespace, name)
        for name in request.services:
            delete_service(core_api, namespace, name)
    if source.exists() and destination.exists():
        raise HTTPException(status_code=409, detail="학생 Workspace 원본과 보관본이 함께 존재합니다.")
    if source.exists():
        move_directory_safely(
            source,
            destination,
            {
                "course_id": request.course_id,
                "student_num": request.student_num,
                "retention_days": request.retention_days,
                "archived_at": int(time.time()),
            },
        )
    return {"archived": True, "archive_key": request.archive_key}


@app.post("/api/workspace/smoke")
async def prepare_workspace_smoke(
    request: SmokeWorkspaceRequest,
    token_payload: dict = Depends(require_service_scope("workspace:smoke", "workspace")),
):
    """릴리스 검증용 NFS 경로를 제한된 이름으로 준비합니다."""
    namespace = resolve_namespace(request.namespace)
    verify_course_namespace(client.CoreV1Api(), namespace, request.course_id)
    try:
        workspace_path, extension_path = prepare_smoke_workspace(request.file_path, request.student_num)
    except RuntimeError as error:
        raise HTTPException(status_code=503, detail=str(error)) from error
    nfs_root = Path(NFS_MOUNT_PATH).resolve()
    return {
        "prepared": True,
        "workspace": str(workspace_path.relative_to(nfs_root)),
        "extensions": str(extension_path.relative_to(nfs_root)),
    }


@app.delete("/api/workspace/smoke")
async def delete_workspace_smoke(
    request: SmokeWorkspaceRequest,
    token_payload: dict = Depends(require_service_scope("workspace:smoke", "workspace")),
):
    """릴리스 검증이 만든 NFS 경로만 삭제합니다."""
    namespace = resolve_namespace(request.namespace)
    verify_course_namespace(client.CoreV1Api(), namespace, request.course_id)
    cleanup_smoke_workspace(request.file_path, request.student_num)
    return {"deleted": True}


@app.post("/api/workspace/starter-code")
async def deploy_starter_code(
    course_id: int = Form(...),
    namespace: str = Form(...),
    dir_name: str = Form(...),
    file: UploadFile = File(...),
    token_payload: dict = Depends(require_service_scope("workspace:write", "workspace")),
):
    """스타터 코드 zip 파일을 모든 학생 워크스페이스에 배포"""
    namespace = resolve_namespace(namespace)
    verify_course_namespace(client.CoreV1Api(), namespace, course_id)
    dir_name = validate_workspace_dir_name(dir_name)

    import glob
    import zipfile
    import tempfile
    import shutil

    class_div = namespace[len(COURSE_NAMESPACE_PREFIX):]
    base_path = str(get_nfs_workspace_path())
    try:
        validate_nfs_mount()
    except RuntimeError as error:
        raise HTTPException(status_code=503, detail=str(error)) from error

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
