# Stage 1: Build 단계 - 의존성 설치
FROM docker.io/library/python:3.9-slim AS builder

WORKDIR /app

# 의존성 파일 복사 및 설치 (설치 경로를 /install 하여 이후 복사)
COPY requirements.txt .
RUN pip install --no-cache-dir --only-binary=:all: --prefix=/install -r requirements.txt

# Stage 2: 최종 이미지
FROM docker.io/library/python:3.9-slim

# Kubernetes securityContext와 동일한 숫자 UID/GID를 사용한다.
RUN groupadd --gid 1000 appuser && \
    useradd --uid 1000 --gid 1000 --create-home appuser

# 빌드 단계에서 설치한 패키지를 복사
COPY --from=builder /install /usr/local

WORKDIR /app

# 소스 코드 복사
COPY . .
RUN chmod -R a+rX /app

# 컨테이너 포트 노출
EXPOSE 5000

# 비루트 사용자로 전환
USER 1000:1000

# Uvicorn을 사용해 FastAPI 앱 실행, 워커 수를 조정해 프로덕션 환경에 적합하게 구성
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "5000", "--workers", "4"]
