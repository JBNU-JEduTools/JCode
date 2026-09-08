package main

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"
)

const maxMetricsBytes = 16 << 20

type gateway struct {
	metricsURL string
	client     *http.Client
	maxAge     time.Duration
	mu         sync.RWMutex
	lastOK     time.Time
}

func successfulSquidScrape(body []byte) bool {
	up := false
	collected := false
	for _, line := range bytes.Split(body, []byte("\n")) {
		line = bytes.TrimSpace(line)
		if len(line) == 0 || line[0] == '#' {
			continue
		}
		fields := bytes.Fields(line)
		if len(fields) < 2 {
			continue
		}
		name := fields[0]
		if bytes.Equal(name, []byte("squid_up")) || bytes.HasPrefix(name, []byte("squid_up{")) {
			up = bytes.Equal(fields[len(fields)-1], []byte("1"))
			continue
		}
		if bytes.HasPrefix(name, []byte("squid_")) && !bytes.HasPrefix(name, []byte("squid_exporter_")) {
			collected = true
		}
	}
	return up && collected
}

func (g *gateway) scrape(ctx context.Context) ([]byte, http.Header, int, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, g.metricsURL, nil)
	if err != nil {
		return nil, nil, 0, err
	}
	resp, err := g.client.Do(req)
	if err != nil {
		return nil, nil, 0, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxMetricsBytes))
	if err != nil {
		return nil, resp.Header, resp.StatusCode, err
	}
	if resp.StatusCode != http.StatusOK {
		return body, resp.Header, resp.StatusCode, fmt.Errorf("exporter returned %s", resp.Status)
	}
	if !successfulSquidScrape(body) {
		return body, resp.Header, resp.StatusCode, fmt.Errorf("successful Squid scrape metrics are missing")
	}
	g.mu.Lock()
	g.lastOK = time.Now()
	g.mu.Unlock()
	return body, resp.Header, resp.StatusCode, nil
}

func (g *gateway) recentlyReady() bool {
	g.mu.RLock()
	lastOK := g.lastOK
	g.mu.RUnlock()
	return !lastOK.IsZero() && time.Since(lastOK) <= g.maxAge
}

func (g *gateway) metrics(w http.ResponseWriter, r *http.Request) {
	body, headers, status, err := g.scrape(r.Context())
	if contentType := headers.Get("Content-Type"); contentType != "" {
		w.Header().Set("Content-Type", contentType)
	}
	if status == 0 {
		status = http.StatusBadGateway
	}
	w.WriteHeader(status)
	_, _ = w.Write(body)
	if err != nil {
		log.Printf("Squid metric collection failed: %v", err)
	}
}

func (g *gateway) ready(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()
	_, _, _, err := g.scrape(ctx)
	if err != nil && !g.recentlyReady() {
		http.Error(w, "Squid metrics are not ready", http.StatusServiceUnavailable)
		return
	}
	w.WriteHeader(http.StatusOK)
	_, _ = io.WriteString(w, "ready\n")
}

func envOrDefault(name, fallback string) string {
	if value := strings.TrimSpace(os.Getenv(name)); value != "" {
		return value
	}
	return fallback
}

func replaceEnv(values []string, name, value string) []string {
	prefix := name + "="
	result := make([]string, 0, len(values)+1)
	for _, item := range values {
		if !strings.HasPrefix(item, prefix) {
			result = append(result, item)
		}
	}
	return append(result, prefix+value)
}

func main() {
	listen := envOrDefault("SQUID_EXPORTER_LISTEN", ":9308")
	internal := envOrDefault("SQUID_EXPORTER_INTERNAL_LISTEN", "127.0.0.1:9309")
	maxAge, err := time.ParseDuration(envOrDefault("SQUID_EXPORTER_READY_MAX_AGE", "30s"))
	if err != nil || maxAge <= 0 {
		log.Fatal("SQUID_EXPORTER_READY_MAX_AGE must be a positive duration")
	}

	child := exec.Command("/usr/local/bin/squid-exporter")
	child.Env = replaceEnv(os.Environ(), "SQUID_EXPORTER_LISTEN", internal)
	child.Stdout = os.Stdout
	child.Stderr = os.Stderr
	if err := child.Start(); err != nil {
		log.Fatalf("start squid exporter: %v", err)
	}

	g := &gateway{
		metricsURL: "http://" + internal + "/metrics",
		client:     &http.Client{Timeout: 10 * time.Second},
		maxAge:     maxAge,
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/metrics", g.metrics)
	mux.HandleFunc("/ready", g.ready)
	mux.HandleFunc("/live", func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })
	server := &http.Server{Addr: listen, Handler: mux, ReadHeaderTimeout: 5 * time.Second}

	stopping := make(chan os.Signal, 1)
	signal.Notify(stopping, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-stopping
		_ = child.Process.Signal(syscall.SIGTERM)
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_ = server.Shutdown(ctx)
	}()
	go func() {
		if err := child.Wait(); err != nil {
			log.Printf("squid exporter exited: %v", err)
		}
		_ = server.Close()
	}()

	if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		log.Fatal(err)
	}
}
