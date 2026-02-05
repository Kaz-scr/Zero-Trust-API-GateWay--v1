package middleware

import (
	"bytes"
	"io"
	"net/http"
	"strings"
)

/*
HTTP REQUEST VALIDATION MIDDLEWARE

WHY THIS EXISTS:
- Reject malformed or abusive requests early
- Reduce memory pressure and parser risk downstream
- Provide a clear, explainable security boundary

WHY IT IS SIMPLE:
- No payload inspection
- No schema validation
- No content parsing
- net/http already does enough; we add guardrails only

FAIL-CLOSED PRINCIPLE:
- If something looks wrong or missing → reject with 400
*/

/*
Configuration (constants only, per requirements)
*/

const (
	// Maximum allowed request body size in bytes.
	// This is a hard cap, not per-route.
	MaxRequestBodyBytes = 1 << 20 // 1 MiB
)

// Allowed content types.
// Exact match or prefix match (e.g. application/json; charset=utf-8).
var AllowedContentTypes = []string{
	"application/json",
	"text/plain",
}

// Headers that must always be present.
var RequiredHeaders = []string{
	"User-Agent",
}

/*
Middleware
*/

func ValidateRequestMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {

		/*
			1. Enforce required headers
			We do this first because it's cheap and avoids work.
		*/

		for _, h := range RequiredHeaders {
			if strings.TrimSpace(r.Header.Get(h)) == "" {
				http.Error(w, "missing required header: "+h, http.StatusBadRequest)
				return
			}
		}

		/*
			2. Enforce Content-Type (only if body is present)
			We do NOT try to parse or validate payload structure.
		*/
		if r.ContentLength > 0 {
			ct := r.Header.Get("Content-Type")
			if !isAllowedContentType(ct) {
				http.Error(w, "invalid Content-Type", http.StatusBadRequest)
				return
			}
		}

		/*
			3. Enforce maximum body size and preserve body for downstream
			http.MaxBytesReader ensures we do not read more than allowed.
			We buffer the body so the proxy receives the full request body.
		*/
		r.Body = http.MaxBytesReader(w, r.Body, MaxRequestBodyBytes)

		body, err := io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, "failed to read request body", http.StatusBadRequest)
			return
		}

		r.Body = io.NopCloser(bytes.NewReader(body))

		next.ServeHTTP(w, r)
	})
}

/*
Helpers
*/

func isAllowedContentType(ct string) bool {
	if ct == "" {
		return false
	}

	// Allow prefix matches to support charset parameters
	for _, allowed := range AllowedContentTypes {
		if strings.HasPrefix(ct, allowed) {
			return true
		}
	}
	return false
}
