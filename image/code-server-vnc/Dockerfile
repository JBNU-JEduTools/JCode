ARG JCODE_CODE_SERVER_BASE=ghcr.io/coder/code-server:4.135.0@sha256:ccd326184d71efc5ebb94155eda7bb30153902342a35dbc8525450d81aa55012
FROM ${JCODE_CODE_SERVER_BASE}
ARG JCODE_CODE_SERVER_BASE_DIGEST=sha256:ccd326184d71efc5ebb94155eda7bb30153902342a35dbc8525450d81aa55012
ARG JCODE_CODE_SERVER_REVISION=local

LABEL org.opencontainers.image.title="code-server-vnc"
LABEL org.opencontainers.image.description="VS Code(code-server) + VNC/novnc environment"
LABEL org.opencontainers.image.authors="OSLAB"
LABEL org.opencontainers.image.licenses="MIT"
LABEL org.opencontainers.image.source="https://github.com/coder/code-server"
LABEL org.opencontainers.image.revision="${JCODE_CODE_SERVER_REVISION}"
LABEL org.opencontainers.image.base.digest="${JCODE_CODE_SERVER_BASE_DIGEST}"
LABEL org.opencontainers.image.base.version="4.135.0"

USER root
ENV DEBIAN_FRONTEND=noninteractive

RUN sed -i 's|http://deb.debian.org|https://deb.debian.org|g' /etc/apt/sources.list.d/debian.sources && \
    apt-get update && apt-get install --no-install-recommends -y \
      tigervnc-standalone-server \
      tigervnc-tools \
      x11-xserver-utils \
      openbox \
      novnc \
      websockify \
      python3 \
      python3-pip \
      python3-ipykernel \
      python3-tk \
      gcc \
      gdb \
      build-essential \
      libc6-dev \
      supervisor \
      netcat-openbsd \
      libxcb-icccm4 \
      libxcb-image0 \
      libxcb-keysyms1 \
      libxcb-render-util0 \
      libxcb-shape0 \
      libxcb-xinerama0 \
      libxcb-xkb1 \
      libxkbcommon-x11-0 \
      libxkbcommon0 \
      fonts-nanum && \
    rm -rf /var/lib/apt/lists/*

# Keep the VNC variant under the same no-AI policy as the browser IDE.
RUN rm -rf /usr/lib/code-server/lib/vscode/extensions/copilot && \
    test ! -e /usr/lib/code-server/lib/vscode/extensions/copilot

RUN mkdir -p /home/coder/.config/pip \
      /home/coder/.config/tigervnc \
      /home/coder/.ipython/profile_default/startup \
      /home/coder/.local/share/code-server \
      /logs && \
    printf '%s\n' '[global]' 'break-system-packages = true' \
      'trusted-host = pypi.org' 'index-url = https://pypi.org/simple' \
      '' '[install]' 'user = true' > /home/coder/.config/pip/pip.conf && \
    printf '%s\n' 'exec openbox-session' > /home/coder/.config/tigervnc/xstartup && \
    chmod +x /home/coder/.config/tigervnc/xstartup && \
    cp /usr/share/novnc/vnc.html /usr/share/novnc/package.json && \
    touch /home/coder/.Xauthority && \
    chown -R 1000:1000 /home/coder /logs

ENV PATH="${PATH}:/home/coder/.local/bin"

COPY supervisor/supervisord.default.conf /etc/supervisor/supervisord.conf

EXPOSE 8080 5900-5910 6080-6100

ENTRYPOINT []
CMD ["/usr/bin/supervisord", "-c", "/etc/supervisor/supervisord.conf"]
