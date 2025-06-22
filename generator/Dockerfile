# Stage 1: Build 단계 - 의존성 설치
FROM python:3.9-slim AS builder

# 빌드에 필요한 패키지 설치 (예: gcc, build-essential)
RUN apt-get update && \
    apt-get install -y gcc build-essential && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /app

# 의존성 파일 복사 및 설치 (설치 경로를 /install 하여 이후 복사)
COPY requirements.txt .
RUN pip install --no-cache-dir --prefix=/install -r requirements.txt

# Stage 2: 최종 이미지
FROM python:3.9-slim

# 비루트 사용자 생성
RUN useradd -m appuser

# 빌드 단계에서 설치한 패키지를 복사
COPY --from=builder /install /usr/local

WORKDIR /app

# 소스 코드 복사
COPY . .

# 컨테이너 포트 노출
EXPOSE 5000

# 비루트 사용자로 전환
USER appuser

# Uvicorn을 사용해 FastAPI 앱 실행, 워커 수를 조정해 프로덕션 환경에 적합하게 구성
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "5000", "--workers", "4"]
