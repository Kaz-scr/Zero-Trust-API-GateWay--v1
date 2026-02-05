package ratelimit

import (
	"context"
	"net"
	"net/http"
	"sync"
	"time"
)

/*
DESIGN OVERVIEW

We use a TOKEN BUCKET per key.

Why token bucket?
- Simple mental model
- Allows short bursts
- Easy to explain in interviews
- Deterministic and safe

Keys:
- Always rate-limit by client IP
- Optionally also rate-limit by authenticated user ID if present

Fail-closed behavior:
- If internal state is unavailable or corrupted, apply a SMALL fallback limit.
- Never allow unlimited traffic.
*/

/*

Configuration (constants only, per requirements)

*/

const (
	// Primary limits
	IPBucketCapacity    = 20
	IPRefillPerSecond   = 5
	UserBucketCapacity  = 40
	UserRefillPerSecond = 10

	// Fallback (very conservative)
	FallbackCapacity = 2
	FallbackRefillPS = 1
)

/*

Clock abstraction (for testability)

*/

type Clock interface {
	Now() time.Time
}

type realClock struct{}

func (realClock) Now() time.Time { return time.Now() }

/*

Token bucket implementation

*/

type bucket struct {
	capacity int
	tokens   float64
	refillPS float64
	last     time.Time
}

func newBucket(capacity int, refillPS int, now time.Time) *bucket {
	return &bucket{
		capacity: capacity,
		tokens:   float64(capacity),
		refillPS: float64(refillPS),
		last:     now,
	}
}

func (b *bucket) allow(now time.Time) bool {
	// Refill tokens
	elapsed := now.Sub(b.last).Seconds()
	b.last = now

	b.tokens += elapsed * b.refillPS
	if b.tokens > float64(b.capacity) {
		b.tokens = float64(b.capacity)
	}

	if b.tokens < 1 {
		return false
	}

	b.tokens -= 1
	return true
}

/*

Limiter

*/

type Limiter struct {
	mu    sync.Mutex
	clock Clock

	ipBuckets   map[string]*bucket
	userBuckets map[string]*bucket
}

// Context key for optional authenticated user ID.
// We intentionally do NOT depend on auth packages.
type userIDKeyType struct{}

var UserIDKey = userIDKeyType{}

func NewLimiter() *Limiter {
	return &Limiter{
		clock:       realClock{},
		ipBuckets:   make(map[string]*bucket),
		userBuckets: make(map[string]*bucket),
	}
}

// SetClock is used only for tests.
func (l *Limiter) SetClock(c Clock) {
	l.clock = c
}

func (l *Limiter) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {

		allowed := l.safeAllow(r.Context(), r.RemoteAddr)
		if !allowed {
			http.Error(w, "rate limit exceeded", http.StatusTooManyRequests)
			return
		}

		next.ServeHTTP(w, r)
	})
}

// Stats returns the count of active IP and user buckets (no sensitive data).
func (l *Limiter) Stats() (ipBuckets, userBuckets int) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return len(l.ipBuckets), len(l.userBuckets)
}

/*

Core decision logic (fail-closed)

*/

func (l *Limiter) safeAllow(ctx context.Context, remoteAddr string) (allowed bool) {
	defer func() {
		// Any panic = fallback limit
		if recover() != nil {
			allowed = fallbackAllow()
		}
	}()

	l.mu.Lock()
	defer l.mu.Unlock()

	now := l.clock.Now()

	ip := extractIP(remoteAddr)
	if ip == "" {
		return fallbackAllow()
	}

	// IP bucket (always enforced)
	ipBucket := l.ipBuckets[ip]
	if ipBucket == nil {
		ipBucket = newBucket(IPBucketCapacity, IPRefillPerSecond, now)
		l.ipBuckets[ip] = ipBucket
	}

	if !ipBucket.allow(now) {
		return false
	}

	// Optional user bucket
	if uid, ok := ctx.Value(UserIDKey).(string); ok && uid != "" {
		userBucket := l.userBuckets[uid]
		if userBucket == nil {
			userBucket = newBucket(UserBucketCapacity, UserRefillPerSecond, now)
			l.userBuckets[uid] = userBucket
		}

		if !userBucket.allow(now) {
			return false
		}
	}

	return true
}

/*

Fallback limiter (very small, hard-coded)

*/

var fallbackMu sync.Mutex
var fallbackBucket = newBucket(FallbackCapacity, FallbackRefillPS, time.Now())

func fallbackAllow() bool {
	fallbackMu.Lock()
	defer fallbackMu.Unlock()
	return fallbackBucket.allow(time.Now())
}

/*

Helpers

*/

func extractIP(remoteAddr string) string {
	host, _, err := net.SplitHostPort(remoteAddr)
	if err != nil {
		return ""
	}
	return host
}
