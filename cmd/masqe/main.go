package main

import (
	"context"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"time"

	"github.com/monolithiq/masqe-control-layer/gateway"
)

func main() {
	policy := env("MASQE_POLICY", "policies/policy.yaml")
	threats := env("MASQE_THREAT_FEED", "policies/threat-feed.yaml")
	db := env("MASQE_DB", "data/masqe.db")
	dashboard := env("MASQE_DASHBOARD", "dashboard/dist")
	if err := os.MkdirAll(filepath.Dir(db), 0o755); err != nil {
		log.Fatal(err)
	}
	cfg, err := gateway.NewConfigManager(policy, threats)
	if err != nil {
		log.Fatal(err)
	}
	cfg.StartRemoteFeed(context.Background(), nil)
	store, err := gateway.OpenStore(db)
	if err != nil {
		log.Fatal(err)
	}
	defer store.Close()
	// Log the chain head outside the database: an anchor for spotting a
	// chain that was later rewritten or truncated.
	if seq, hash := store.AuditChainHead(); seq > 0 {
		log.Printf("audit chain head: entry %d %s", seq, hash)
	}
	semanticURL := env("MASQE_AI_GUARD_URL", "http://127.0.0.1:8090")
	semanticTimeout, _ := strconv.Atoi(env("MASQE_SEMANTIC_TIMEOUT_MS", "1500"))
	analyzer := gateway.ResilientAnalyzer{Primary: gateway.HTTPSemanticClient{URL: semanticURL, Client: &http.Client{Timeout: time.Duration(semanticTimeout) * time.Millisecond}}, Fallback: gateway.UnavailableAnalyzer{}}
	engine := &gateway.Engine{Config: cfg, Store: store, Semantic: analyzer,
		Explainer: gateway.HTTPExplanationClient{URL: semanticURL, Client: &http.Client{Timeout: 48 * time.Second}},
		PII:       gateway.HTTPNERClient{URL: semanticURL, Client: &http.Client{Timeout: 2 * time.Second}}}
	server := gateway.NewServer(engine, dashboard)
	// Loopback by default: the sample API keys are public. Docker sets
	// MASQE_ADDR=0.0.0.0:8080 explicitly behind its own port mapping.
	addr := env("MASQE_ADDR", "127.0.0.1:8080")
	log.Printf("MASQE gateway listening on %s", addr)
	httpServer := &http.Server{Addr: addr, Handler: server.Handler(), ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 30 * time.Second, WriteTimeout: 90 * time.Second, IdleTimeout: 120 * time.Second}
	log.Fatal(httpServer.ListenAndServe())
}
func env(k, d string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return d
}
