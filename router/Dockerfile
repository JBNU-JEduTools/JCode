# 1. 빌드 스테이지 (Node.js 의존성 설치)
FROM node:18-alpine AS build
WORKDIR /app

# package.json과 package-lock.json을 먼저 복사하여 캐시 활용
COPY package*.json ./

# Production 환경에서 의존성만 설치
RUN npm ci --omit=dev

# 2. 런타임 스테이지 (Squid + Node.js 실행)
FROM node:18-alpine

WORKDIR /app

# Squid 및 필수 패키지 설치
RUN apk add --no-cache squid supervisor

# 실행 환경은 Squid ConfigMap을 마운트한다. 이미지 단독 실행 시에는 deny-all을 기본값으로 사용한다.
RUN printf '%s\n' \
    'http_port 3000' \
    'http_access deny all' \
    'cache deny all' \
    'cache_dir null /dev/null' \
    'cache_mem 0 MB' \
    > /etc/squid/squid.conf

# 환경별 값이 없는 공통 supervisor 설정은 이미지에 포함한다.
RUN printf '%s\n' \
    '[supervisord]' \
    'nodaemon=true' \
    '' \
    '[program:squid]' \
    'command=/usr/sbin/squid -N -f /etc/squid/squid.conf' \
    'autostart=true' \
    'autorestart=true' \
    'stderr_logfile=/var/log/squid.err.log' \
    'stdout_logfile=/var/log/squid.out.log' \
    '' \
    '[program:node]' \
    'command=node /app/server.js' \
    'autostart=true' \
    'autorestart=true' \
    'stderr_logfile=/var/log/node.err.log' \
    'stdout_logfile=/var/log/node.out.log' \
    > /etc/supervisord.conf

# 빌드된 Node.js 의존성 복사
COPY --from=build /app/node_modules /app/node_modules

# Node.js 애플리케이션 복사
COPY . .

# 환경 변수 설정
ENV NODE_ENV=production
ENV PORT=3001

# 포트 설정 (Node.js, Aquid)
EXPOSE 3001 3000

# Supervisor 실행 (Squid + Node.js 함께 실행)
CMD ["/usr/bin/supervisord", "-c", "/etc/supervisord.conf"]
