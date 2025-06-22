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
RUN echo "http://mirror.xtom.com.hk/alpine/latest-stable/main" > /etc/apk/repositories \
    && apk update \
    && apk add squid supervisor \
    && rm -rf /var/cache/apk/*

# Squid 설정 파일 복사
COPY squid/squid.conf /etc/squid/squid.conf

# Supervisor 설정 파일 복사
COPY supervisor/supervisord.conf /etc/supervisord.conf

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
