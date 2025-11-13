# === Builder Stage ===
FROM codercom/code-server:4.98.0 AS builder

USER root
ENV DEBIAN_FRONTEND=noninteractive

# 미러 서버 변경 (한국 미러: ftp.kr.debian.org)
RUN sed -i 's|http://deb.debian.org/debian|http://ftp.kr.debian.org/debian|g' /etc/apt/sources.list.d/debian.sources && \
    sed -i 's|http://deb.debian.org/debian-security|http://ftp.kr.debian.org/debian-security|g' /etc/apt/sources.list.d/debian.sources

# 필수 패키지 설치 (최종 스테이지에서는 runit 대신 supervisord를 사용할 예정)
RUN apt-get update && apt-get install --no-install-recommends -y \
    tigervnc-standalone-server \
    tigervnc-tools \
    x11-xserver-utils \
    openbox \
    novnc \
    websockify \
    python3-tk && \
    rm -rf /var/lib/apt/lists/*

# Openbox 세션 실행 설정 (최소한의 GUI 환경)
RUN echo "exec openbox-session" > ~/.xsession && \
    echo "exec openbox-session" > ~/.xinitrc

# VNC 암호 설정 (비밀번호 "password"로 설정)
RUN mkdir -p /root/.vnc && \
    echo "password" | vncpasswd -f > /root/.vnc/passwd && \
    chmod 600 /root/.vnc/passwd

# VNC 서버 실행 테스트 (화면 :1) - 설정 확인용으로 실행 후 종료
RUN vncserver :1 -geometry 1280x800 -depth 24 -passwd /root/.vnc/passwd && \
    vncserver -kill :1

# VNC 세션에 openbox 실행 (VNC 접속 시 최소한의 창 관리자만 실행)
RUN echo "exec openbox-session" > ~/.vnc/xstartup && \
    chmod +x ~/.vnc/xstartup

# noVNC가 정상 동작하도록 패키지.json 파일 복사 (workaround)
RUN cp /usr/share/novnc/vnc.html /usr/share/novnc/package.json

# 필요한 설정 파일들을 /runtime 디렉토리로 복사 (최종 스테이지에 전달할 파일)
RUN mkdir -p /runtime && \
    cp -r /root/.vnc /runtime/ && \
    cp -r ~/.xsession /runtime/ && \
    cp -r ~/.xinitrc /runtime/ && \
    cp -r /usr/share/novnc /runtime/novnc && \
    mkdir -p /runtime/supervisor
# supervisord.conf는 나중에 Final Stage에서 복사할 예정이므로 빌더 스테이지에선 생성하지 않아도 됩니다.

# === Final Stage ===
FROM codercom/code-server:4.98.0

LABEL org.opencontainers.image.title="code-server-vnc"
LABEL org.opencontainers.image.description="VS Code(code-server) + VNC/novnc 환경 이미지"
LABEL org.opencontainers.image.authors="OSLAB"
LABEL org.opencontainers.image.licenses="MIT"
LABEL org.opencontainers.image.source="https://github.com/coder/code-server"

USER root
ENV DEBIAN_FRONTEND=noninteractive

# 미러 서버 변경 (한국 미러: ftp.kr.debian.org)
RUN sed -i 's|http://deb.debian.org/debian|http://ftp.kr.debian.org/debian|g' /etc/apt/sources.list.d/debian.sources && \
    sed -i 's|http://deb.debian.org/debian-security|http://ftp.kr.debian.org/debian-security|g' /etc/apt/sources.list.d/debian.sources

# 최종 이미지에서는 빌더에서 설정한 내용만 복사 (필요한 런타임 설정 파일)
COPY --from=builder /runtime/ /runtime/

# 최종 스테이지에서 필요한 패키지 설치
# 여기서 netcat-openbsd는 nc 명령으로 포트 상태 체크에 필요하므로 반드시 설치해야 합니다.
RUN apt-get update && apt-get install --no-install-recommends -y \
    tigervnc-standalone-server \
    tigervnc-tools \
    x11-xserver-utils \
    openbox \
    novnc \
    websockify \
    python3 \
    python3-pip \
    python3-tk \
    gcc \
    libc6-dev \
    supervisor \
    netcat-openbsd && \
    rm -rf /var/lib/apt/lists/*

# coder 유저의 pip 설정 추가 (break-system-packages)
RUN mkdir -p /home/coder/.config/pip && \
    echo "[global]\n \
        break-system-packages = true\n \
        trusted-host = pypi.org\n \
        index-url = https://pypi.org/simple\n\n \
        [install]\n \
        user = true" > /home/coder/.config/pip/pip.conf

ENV PATH="${PATH}:/home/coder/.local/bin"

# Jupyter 기본 패키지 설치 (가상환경 없이)
RUN mkdir -p /home/coder/.ipython/profile_default/startup
RUN pip3 install --upgrade pip --break-system-packages && \
    pip3 install ipykernel --break-system-packages && \
    python3 -m ipykernel install --user --name=python3 --display-name "Python 3 (System)"

# 설정 파일들을 제 위치로 복사
RUN cp -r /runtime/.vnc /home/coder/ && \
    cp -r /runtime/.xsession /home/coder/ && \
    cp -r /runtime/.xinitrc /home/coder/ && \
    cp -r /runtime/novnc /usr/share/novnc && \
    touch /home/coder/.Xauthority && \
    mkdir -p /home/coder/.local/share/code-server && \
    mkdir -p /logs && \
    chown -R 1000:1000 /logs && \
    chown -R 1000:1000 /home/coder && \
    chown -R 1000:1000 /home/coder/.ipython/profile_default/startup

# supervisord.conf 복사 (Docker build 컨텍스트 내 supervisor 디렉토리에 위치)
COPY supervisor/supervisord.conf /etc/supervisor/supervisord.conf

# 포트 개방 (code-server:8080, VNC:5900~5910, websockify(noVNC):6080~6100)
EXPOSE 8080 5900-5910 6080-6100

# supervisord를 통해 모든 서비스 실행 (nodaemon 옵션이 supervisord.conf에 설정되어 있음)
ENTRYPOINT []
CMD ["/usr/bin/supervisord", "-c", "/etc/supervisor/supervisord.conf"]
