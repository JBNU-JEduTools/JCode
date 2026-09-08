ARG JCODE_CODE_SERVER_BASE=ghcr.io/coder/code-server:4.135.0@sha256:ccd326184d71efc5ebb94155eda7bb30153902342a35dbc8525450d81aa55012
FROM ${JCODE_CODE_SERVER_BASE}
ARG JCODE_CODE_SERVER_BASE_DIGEST=sha256:ccd326184d71efc5ebb94155eda7bb30153902342a35dbc8525450d81aa55012
ARG JCODE_CODE_SERVER_REVISION=local

LABEL org.opencontainers.image.title="JCode IDE"
LABEL org.opencontainers.image.description="JCode - 전북대학교 웹 IDE 플랫폼"
LABEL org.opencontainers.image.authors="OSLAB"
LABEL org.opencontainers.image.licenses="MIT"
LABEL org.opencontainers.image.source="https://github.com/mindungil/JCode-CodeServer"
LABEL org.opencontainers.image.revision="${JCODE_CODE_SERVER_REVISION}"
LABEL org.opencontainers.image.base.digest="${JCODE_CODE_SERVER_BASE_DIGEST}"
LABEL org.opencontainers.image.base.version="4.135.0"

USER root
ENV DEBIAN_FRONTEND=noninteractive

# 필요한 패키지 설치: gcc, python3, python3-pip
RUN sed -i 's|http://deb.debian.org|https://deb.debian.org|g' /etc/apt/sources.list.d/debian.sources && \
    if ! command -v gcc >/dev/null || ! command -v gdb >/dev/null || ! command -v python3 >/dev/null; then \
      apt-get update && apt-get install --no-install-recommends -y \
        gcc \
        gdb \
        build-essential \
        libc6-dev \
        python3 \
        python3-pip && \
      rm -rf /var/lib/apt/lists/*; \
    fi

# JCode does not provide AI coding assistants, including the extension bundled
# with recent upstream VS Code releases.
RUN rm -rf /usr/lib/code-server/lib/vscode/extensions/copilot && \
    test ! -e /usr/lib/code-server/lib/vscode/extensions/copilot

EXPOSE 8080

USER coder
WORKDIR /home/coder/project

# Keep the upstream workbench and settings intact. Kubernetes supplies the
# workspace-specific arguments and mounts.
ENTRYPOINT ["/usr/bin/dumb-init", "--", "/usr/bin/code-server"]
CMD ["--bind-addr", "0.0.0.0:8080", "--auth", "none", "/home/coder/project"]
