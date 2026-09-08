FROM golang:1.24-alpine@sha256:8bee1901f1e530bfb4a7850aa7a479d17ae3a18beb6e09064ed54cfd245b7191 AS readiness-builder
WORKDIR /src
COPY go.mod main.go ./
RUN CGO_ENABLED=0 go build -trimpath -ldflags='-s -w' -o /out/squid-exporter-supervisor .

FROM boynux/squid-exporter:v1.13.0@sha256:a955565560feffccdd765da12e046f00f6410404bb9f55a055543602da2e929b
COPY --from=readiness-builder /out/squid-exporter-supervisor /usr/local/bin/squid-exporter-supervisor
ENV SQUID_EXPORTER_LISTEN=:9308 \
    SQUID_EXPORTER_INTERNAL_LISTEN=127.0.0.1:9309 \
    SQUID_EXPORTER_READY_MAX_AGE=30s
EXPOSE 9308
ENTRYPOINT ["/usr/local/bin/squid-exporter-supervisor"]
