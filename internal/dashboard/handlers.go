package dashboard

import (
	"encoding/json"
	"net/http"
	"strconv"

	"Zero-TrustAPIGateWayServer/internal/audit"
	"Zero-TrustAPIGateWayServer/internal/policy"
)

// LimiterStats is the interface for rate limit statistics.
type LimiterStats interface {
	Stats() (ipBuckets, userBuckets int)
}

// Handlers holds dependencies for dashboard API endpoints.
type Handlers struct {
	Stats       *StatsCollector
	AuditPath   string
	PolicyEngine *policy.Engine
	Limiter     LimiterStats
}

// ServeAPI routes dashboard API requests to the appropriate handler.
func (h *Handlers) ServeAPI(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	switch r.URL.Path {
	case "/api/dashboard/stats":
		h.serveStats(w)
	case "/api/dashboard/audit":
		h.serveAudit(w, r)
	case "/api/dashboard/policies":
		h.servePolicies(w)
	case "/api/dashboard/status":
		h.serveStatus(w)
	default:
		http.NotFound(w, r)
	}
}

func (h *Handlers) serveStats(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "application/json")
	allow, deny, uptime := h.Stats.Snapshot()
	json.NewEncoder(w).Encode(map[string]interface{}{
		"allow":          allow,
		"deny":           deny,
		"uptime_seconds": int64(uptime.Seconds()),
	})
}

func (h *Handlers) serveAudit(w http.ResponseWriter, r *http.Request) {
	limit := 50
	if s := r.URL.Query().Get("limit"); s != "" {
		if n, err := strconv.Atoi(s); err == nil && n > 0 && n <= 200 {
			limit = n
		}
	}

	entries, err := audit.ReadLastEntries(h.AuditPath, limit)
	if err != nil {
		http.Error(w, "failed to read audit log", http.StatusInternalServerError)
		return
	}

	type entryDTO struct {
		Timestamp string `json:"timestamp"`
		Method    string `json:"method"`
		Path      string `json:"path"`
		Decision  string `json:"decision"`
		Reason    string `json:"reason"`
	}

	dtos := make([]entryDTO, len(entries))
	for i, e := range entries {
		dtos[i] = entryDTO{
			Timestamp: e.Timestamp.Format("2006-01-02T15:04:05Z07:00"),
			Method:    e.Method,
			Path:      e.Path,
			Decision:  e.Decision,
			Reason:    e.Reason,
		}
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{"entries": dtos})
}

func (h *Handlers) servePolicies(w http.ResponseWriter) {
	rules := h.PolicyEngine.GetPolicies()
	type policyDTO struct {
		Method string   `json:"method"`
		Path   string   `json:"path"`
		Roles  []string `json:"roles"`
	}
	dtos := make([]policyDTO, len(rules))
	for i, r := range rules {
		dtos[i] = policyDTO{Method: r.Method, Path: r.Path, Roles: r.Roles}
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{"policies": dtos})
}

func (h *Handlers) serveStatus(w http.ResponseWriter) {
	var ipBuckets, userBuckets int
	if h.Limiter != nil {
		ipBuckets, userBuckets = h.Limiter.Stats()
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"rate_limit": map[string]int{
			"ip_buckets":   ipBuckets,
			"user_buckets": userBuckets,
		},
	})
}
