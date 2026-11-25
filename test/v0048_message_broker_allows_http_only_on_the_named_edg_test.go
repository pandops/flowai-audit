package test

// Requirement: message-broker allows HTTP only on the named edges. audit has
// no HTTP edge: it serves only /v1/livez and /v1/readyz.

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/pandops/flowai-audit/internal/health"
)

func TestV0048MessageBrokerHTTPOnlyProbes(t *testing.T) {
	t.Run("Service offers no internal HTTP API", func(t *testing.T) {
		router := health.NewRouter(health.Check{Name: "database", Fn: func(context.Context) error { return nil }})
		for _, tc := range []struct{ method, path string }{
			{http.MethodGet, "/v1/audit"},
			{http.MethodGet, "/v1/audit/5120"},
			{http.MethodGet, "/ui/v1/teams/3/audit"},
			{http.MethodPost, "/v1/audit"},
			{http.MethodGet, "/"},
			{http.MethodGet, "/metrics"},
			{http.MethodPost, "/v1/readyz"},
			{http.MethodDelete, "/v1/livez"},
		} {
			rec := httptest.NewRecorder()
			router.ServeHTTP(rec, httptest.NewRequest(tc.method, tc.path, nil))
			if rec.Code != http.StatusNotFound {
				t.Errorf("%s %s = %d, want 404", tc.method, tc.path, rec.Code)
			}
		}
		for _, path := range []string{"/v1/livez", "/v1/readyz"} {
			rec := httptest.NewRecorder()
			router.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, path, nil))
			if rec.Code != http.StatusOK {
				t.Errorf("GET %s = %d, want 200", path, rec.Code)
			}
			if len(rec.Body.Bytes()) > 32 {
				t.Errorf("GET %s carries data: %s", path, rec.Body.String())
			}
		}
	})
}
