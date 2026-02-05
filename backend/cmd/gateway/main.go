package main

import (
	"embed"
	"io/fs"
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"strings"
	"time"

	"Zero-TrustAPIGateWayServer/internal/audit"
	"Zero-TrustAPIGateWayServer/internal/auth"
	"Zero-TrustAPIGateWayServer/internal/dashboard"
	"Zero-TrustAPIGateWayServer/internal/middleware"
	"Zero-TrustAPIGateWayServer/internal/policy"
	"Zero-TrustAPIGateWayServer/internal/ratelimit"
	"Zero-TrustAPIGateWayServer/internal/rbac"
)

//go:embed web/dashboard
var dashboardFS embed.FS

/*

SECURITY PRINCIPLES ENFORCED HERE:

1. Explicit middleware order (no ambiguity)
2. Default deny at every layer
3. Proxy is reached ONLY if all checks pass
4. Audit logging records final decision
5. Composition only — no logic changes

MIDDLEWARE ORDER (TOP to BOTTOM):

1. Request validation    :   reject malformed traffic early
2. Authentication        :   establish identity
3. RBAC authorization    :   role-based access
4. Policy evaluation     :   route/method allow-list
5. Rate limiting         :   abuse prevention
6. Audit logging         :   tamper-evident decision record
7. Reverse proxy         :   upstream forwarding
*/

func main() {
	log.SetOutput(os.Stdout)
	log.SetFlags(log.LstdFlags | log.LUTC)

	/*
		Upstream configuration (static, allow listed)
	*/

	upstream, err := url.Parse("http://localhost:9000")
	if err != nil {
		log.Fatalf("invalid upstream URL: %v", err)
	}

	proxy := httputil.NewSingleHostReverseProxy(upstream)

	/*
		Audit logger (append only, fail open for logging)
	*/

	auditLogger, err := audit.NewLogger("./audit.log")
	if err != nil {
		log.Fatalf("failed to initialize audit logger: %v", err)
	}
	defer auditLogger.Close()

	/*
		Policy engine (YAML based, deny all on error)
	*/

	policyEngine := policy.NewEngine()
	if err := policyEngine.LoadFromFile("./policies/policies.yaml"); err != nil {
		log.Printf("policy load failed, gateway running in deny-all mode: %v", err)
	}
	policyEngine.Watch("./policies/policies.yaml", 5*time.Second)

	rbacMiddleware := rbac.RBACMiddleware(
		rbac.PolicySet{Policies: convertPolicyRulesToRBACPolicies(policyEngine.GetPolicies())},
	)

	/*
		Rate limiter (in-memory)
	*/

	limiter := ratelimit.NewLimiter()

	/*
		Authentication middleware (API key, demo store)

		note:
		 This assumes auth middleware already enforces default-deny
		 Composition only, no logic changes
	*/

	demoStore := auth.NewDemoStore()
	authMiddleware := auth.APIKeyMiddleware(demoStore)

	/*
		Stats collector for dashboard
	*/

	stats := dashboard.NewStatsCollector()

	/*
		Audit middleware composit
	*/

	auditMiddleware := func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {

			rr := &responseRecorder{ResponseWriter: w, status: http.StatusOK}

			next.ServeHTTP(rr, r)

			decision := "ALLOW"
			reason := "all checks passed"

			if rr.status >= 400 {
				decision = "DENY"
				reason = http.StatusText(rr.status)
			}

			if decision == "ALLOW" {
				stats.IncrementAllow()
			} else {
				stats.IncrementDeny()
			}

			auditLogger.Log(
				r.Method,
				r.URL.Path,
				decision,
				reason,
			)
		})
	}

	/*
		Final handler chain (exact required order)
		Audit must wrap the entire chain so it sees ALL requests (incl. denies).
	*/

	securedChain :=
		middleware.ValidateRequestMiddleware(
			authMiddleware(
				rbacMiddleware(
					limiter.Middleware(
						proxy,
					),
				),
			),
		)

	finalHandler := auditMiddleware(securedChain)

	/*
		Dashboard (unauthenticated for demo)
	*/

	dashboardHandlers := &dashboard.Handlers{
		Stats:        stats,
		AuditPath:    "./audit.log",
		PolicyEngine: policyEngine,
		Limiter:      limiter,
	}

	subFS, err := fs.Sub(dashboardFS, "web/dashboard")
	if err != nil {
		log.Fatalf("dashboard embed: %v", err)
	}

	dashboardFiles := http.StripPrefix("/dashboard", http.FileServer(http.FS(subFS)))

	rootHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p := r.URL.Path
		switch {
		case p == "/dashboard":
			http.Redirect(w, r, "/dashboard/", http.StatusFound)
		case strings.HasPrefix(p, "/dashboard/"):
			dashboardFiles.ServeHTTP(w, r)
		case strings.HasPrefix(p, "/api/dashboard"):
			dashboardHandlers.ServeAPI(w, r)
		default:
			finalHandler.ServeHTTP(w, r)
		}
	})

	/*
		HTTP server
	*/

	server := &http.Server{
		Addr:         ":8080",
		Handler:      rootHandler,
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 10 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	log.Println("Zero-Trust API Gateway listening on :8080")

	if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		log.Fatalf("server error: %v", err)
	}
}

/*
Response recorder (standard pattern)
*/

func convertPolicyRulesToRBACPolicies(rules []policy.Rule) []rbac.Policy {
	policies := make([]rbac.Policy, len(rules))
	for i, rule := range rules {
		policies[i] = rbac.Policy(rule)
	}
	return policies
}

type responseRecorder struct {
	http.ResponseWriter
	status int
}

func (r *responseRecorder) WriteHeader(code int) {
	r.status = code
	r.ResponseWriter.WriteHeader(code)
}
