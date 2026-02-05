package dashboard

import (
	"sync/atomic"
	"time"
)

type StatsCollector struct {
	allowCount atomic.Int64
	denyCount  atomic.Int64
	startedAt  time.Time
}

func NewStatsCollector() *StatsCollector {
	return &StatsCollector{startedAt: time.Now()}
}

func (s *StatsCollector) IncrementAllow() {
	s.allowCount.Add(1)
}

func (s *StatsCollector) IncrementDeny() {
	s.denyCount.Add(1)
}

func (s *StatsCollector) Snapshot() (allow, deny int64, uptime time.Duration) {
	return s.allowCount.Load(), s.denyCount.Load(), time.Since(s.startedAt)
}
