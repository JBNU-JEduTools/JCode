FROM codercom/code-server:4.98.0

LABEL org.opencontainers.image.title="code-server"
LABEL org.opencontainers.image.description="VS Code(code-server) 환경 이미지"
LABEL org.opencontainers.image.authors="OSLAB"
LABEL org.opencontainers.image.licenses="MIT"
LABEL org.opencontainers.image.source="https://github.com/coder/code-server"

USER root
ENV DEBIAN_FRONTEND=noninteractive

# 미러 서버 변경 (한국 미러: ftp.kr.debian.org)
RUN sed -i 's|http://deb.debian.org/debian|http://ftp.kr.debian.org/debian|g' /etc/apt/sources.list.d/debian.sources && \
    sed -i 's|http://deb.debian.org/debian-security|http://ftp.kr.debian.org/debian-security|g' /etc/apt/sources.list.d/debian.sources

# 필요한 패키지 설치: gcc, python3, python3-pip
RUN apt-get update && apt-get install --no-install-recommends -y \
    gcc \
    build-essential \
    libc6-dev \
    python3 \
    python3-pip && \
    rm -rf /var/lib/apt/lists/*

# 필요 시 포트 노출 (code-server 기본 포트)
EXPOSE 8080

# 기본 사용자로 전환 (code-server 이미지는 기본적으로 'coder' 사용자를 사용)
USER coder

# 기본 CMD는 코드서버 실행 (이미지 기본 ENTRYPOINT/CMD를 그대로 사용 가능)
CMD ["code-server", "--bind-addr", "0.0.0.0:8080", "--auth", "none"]
