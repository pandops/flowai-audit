// Package health serves audit's only HTTP routes: /v1/livez and /v1/readyz.
package health

import (
	"context"
	"net/http"
	"time"
)

// Check is one readiness dependency.
type Check struct {
	Name string
	Fn   func(ctx context.Context) error
}

// NewRouter returns the probe handler; every other path is 404.
func NewRouter(checks ...Check) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /v1/livez", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok\n"))
	})
	mux.HandleFunc("GET /v1/readyz", func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
		defer cancel()
		for _, c := range checks {
			if err := c.Fn(ctx); err != nil {
				w.WriteHeader(http.StatusServiceUnavailable)
				_, _ = w.Write([]byte("not ready\n"))
				return
			}
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok\n"))
	})
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet || (r.URL.Path != "/v1/livez" && r.URL.Path != "/v1/readyz") {
			http.NotFound(w, r)
			return
		}
		mux.ServeHTTP(w, r)
	})
}
