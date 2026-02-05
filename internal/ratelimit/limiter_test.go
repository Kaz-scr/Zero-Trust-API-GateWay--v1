package ratelimit

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

/*
Fake clock so tests never sleep.
*/

type fakeClock struct {
	now time.Time
}

func (f *fakeClock) Now() time.Time {
	return f.now
}

func (f *fakeClock) Advance(d time.Duration) {
	f.now = f.now.Add(d)
}

func newTestLimiter() (*Limiter, *fakeClock) {
	fc := &fakeClock{now: time.Unix(0, 0)}
	l := NewLimiter()
	l.SetClock(fc)
	return l, fc
}

func TestAllowedUnderLimit(t *testing.T) {
	limiter, _ := newTestLimiter()

	handler := limiter.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest("GET", "/", nil)
	req.RemoteAddr = "1.2.3.4:1234"
	rr := httptest.NewRecorder()

	for i := 0; i < 5; i++ {
		handler.ServeHTTP(rr, req)
		if rr.Code != http.StatusOK {
			t.Fatalf("expected allowed request")
		}
	}
}

func TestBlockedOverLimit(t *testing.T) {
	limiter, _ := newTestLimiter()

	handler := limiter.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest("GET", "/", nil)
	req.RemoteAddr = "5.5.5.5:9999"

	var code int
	for i := 0; i < IPBucketCapacity+1; i++ {
		rr := httptest.NewRecorder()
		handler.ServeHTTP(rr, req)
		code = rr.Code
	}

	if code != http.StatusTooManyRequests {
		t.Fatalf("expected 429, got %d", code)
	}
}

func TestIndependentLimitsPerIP(t *testing.T) {
	limiter, _ := newTestLimiter()

	handler := limiter.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	reqA := httptest.NewRequest("GET", "/", nil)
	reqA.RemoteAddr = "10.0.0.1:1"

	reqB := httptest.NewRequest("GET", "/", nil)
	reqB.RemoteAddr = "10.0.0.2:2"

	rrA := httptest.NewRecorder()
	rrB := httptest.NewRecorder()

	handler.ServeHTTP(rrA, reqA)
	handler.ServeHTTP(rrB, reqB)

	if rrA.Code != http.StatusOK || rrB.Code != http.StatusOK {
		t.Fatal("expected independent IP limits")
	}
}

func TestFallbackOnInternalError(t *testing.T) {
	limiter, _ := newTestLimiter()

	// Corrupt internal state deliberately
	limiter.ipBuckets = nil

	handler := limiter.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest("GET", "/", nil)
	req.RemoteAddr = "8.8.8.8:80"

	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	// Fallback allows only a very small number; first request should pass
	if rr.Code != http.StatusOK {
		t.Fatalf("expected fallback allow, got %d", rr.Code)
	}
}

func TestUserIDLimitApplied(t *testing.T) {
	limiter, _ := newTestLimiter()

	handler := limiter.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	ctx := context.WithValue(context.Background(), UserIDKey, "user-1")

	req := httptest.NewRequest("GET", "/", nil).WithContext(ctx)
	req.RemoteAddr = "9.9.9.9:123"

	for i := 0; i < UserBucketCapacity; i++ {
		rr := httptest.NewRecorder()
		handler.ServeHTTP(rr, req)
	}

	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusTooManyRequests {
		t.Fatalf("expected user-level 429")
	}
}
