package server

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"io/fs"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// HTTP serves the dashboard, a small JSON API, and DNS-over-HTTPS (/dns-query)
// so phones and browsers can use dnsguard as their encrypted DNS too.
func (s *Server) HTTP(static fs.FS, token string) http.Handler {
	mux := http.NewServeMux()
	auth := func(h http.HandlerFunc) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			if token != "" && r.Header.Get("Authorization") != "Bearer "+token && r.URL.Query().Get("token") != token {
				http.Error(w, "unauthorized", http.StatusUnauthorized)
				return
			}
			h(w, r)
		}
	}
	mux.Handle("GET /", http.FileServerFS(static))

	mux.HandleFunc("GET /api/summary", auth(func(w http.ResponseWriter, r *http.Request) {
		sum := s.Stats.Summary(time.Now())
		hits, misses := s.cache.Counters()
		writeJSON(w, map[string]any{"summary": sum, "blocklist_size": s.cfg.Block.Len(), "cache_size": s.cache.Len(),
			"cache_hits": hits, "cache_misses": misses, "upstreams": s.pool.Status()})
	}))

	mux.HandleFunc("GET /api/queries", auth(func(w http.ResponseWriter, r *http.Request) {
		n, _ := strconv.Atoi(r.URL.Query().Get("n"))
		if n <= 0 || n > 1000 {
			n = 200
		}
		q := strings.ToLower(r.URL.Query().Get("q"))
		only := r.URL.Query().Get("result")
		writeJSON(w, s.Stats.Recent(n, func(e Entry) bool {
			if only != "" && e.Result != only {
				return false
			}
			return q == "" || strings.Contains(e.Name, q) || strings.HasPrefix(e.Client, q)
		}))
	}))

	mux.HandleFunc("GET /api/check", auth(func(w http.ResponseWriter, r *http.Request) {
		name := r.URL.Query().Get("name")
		blocked, rule := s.cfg.Block.Match(name)
		writeJSON(w, map[string]any{"name": name, "blocked": blocked, "rule": rule})
	}))

	mux.HandleFunc("POST /api/allow", auth(func(w http.ResponseWriter, r *http.Request) {
		name := strings.TrimSpace(r.FormValue("name"))
		if name == "" {
			http.Error(w, "name required", http.StatusBadRequest)
			return
		}
		s.cfg.Block.Allow(name)
		writeJSON(w, map[string]any{"allowed": name})
	}))

	mux.HandleFunc("POST /api/cache/flush", auth(func(w http.ResponseWriter, r *http.Request) {
		s.cache.Flush()
		writeJSON(w, map[string]any{"flushed": true})
	}))

	// RFC 8484: GET ?dns=<base64url> or POST application/dns-message.
	// Registered per method: a method-less "/dns-query" conflicts with
	// "GET /" in Go 1.22+ routing and panics at startup.
	doh := func(w http.ResponseWriter, r *http.Request) {
		var q []byte
		var err error
		switch r.Method {
		case http.MethodGet:
			q, err = base64.RawURLEncoding.DecodeString(r.URL.Query().Get("dns"))
		case http.MethodPost:
			if !strings.HasPrefix(r.Header.Get("Content-Type"), "application/dns-message") {
				http.Error(w, "content-type must be application/dns-message", http.StatusUnsupportedMediaType)
				return
			}
			q, err = io.ReadAll(io.LimitReader(r.Body, 65535))
		}
		if err != nil || len(q) < 12 {
			http.Error(w, "bad dns message", http.StatusBadRequest)
			return
		}
		ip, _, _ := net.SplitHostPort(r.RemoteAddr)
		ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
		defer cancel()
		resp := s.Handle(ctx, q, ip, "doh")
		if resp == nil {
			http.Error(w, "bad dns message", http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Type", "application/dns-message")
		w.Header().Set("Cache-Control", "max-age=0")
		w.Write(resp)
	}
	mux.HandleFunc("GET /dns-query", doh)
	mux.HandleFunc("POST /dns-query", doh)

	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, "ok\n") })
	return mux
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	enc.Encode(v)
}
