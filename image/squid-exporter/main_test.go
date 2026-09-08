package main

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestSuccessfulSquidScrape(t *testing.T) {
	if !successfulSquidScrape([]byte("squid_up{host=\"squid\"} 1\nsquid_requests 1\n")) {
		t.Fatal("expected successful Squid scrape to be detected")
	}
	if successfulSquidScrape([]byte("squid_up{host=\"squid\"} 0\nsquid_exporter_build_info 1\n")) {
		t.Fatal("failed Squid scrape must not make the exporter ready")
	}
	if successfulSquidScrape([]byte("go_gc_duration_seconds 1\n")) {
		t.Fatal("non-Squid metrics must not make the exporter ready")
	}
}

func TestReadyFailsWithoutSquidMetrics(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("go_gc_duration_seconds 1\n"))
	}))
	defer upstream.Close()
	g := &gateway{metricsURL: upstream.URL, client: upstream.Client(), maxAge: time.Second}

	recorder := httptest.NewRecorder()
	g.ready(recorder, httptest.NewRequest(http.MethodGet, "/ready", nil))

	if recorder.Code != http.StatusServiceUnavailable {
		t.Fatalf("expected 503, got %d", recorder.Code)
	}
}
