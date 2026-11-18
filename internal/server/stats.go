package server

import (
	"sort"
	"sync"
	"time"
)

// Entry is one line of the query log.
type Entry struct {
	Time      time.Time     `json:"time"`
	Client    string        `json:"client"`
	Name      string        `json:"name"`
	Type      string        `json:"type"`
	Transport string        `json:"transport"`
	Result    string        `json:"result"` // blocked | cached | forwarded | error
	Rule      string        `json:"rule,omitempty"`
	Upstream  string        `json:"upstream,omitempty"`
	Rcode     int           `json:"rcode"`
	Answers   []string      `json:"answers,omitempty"`
	Error     string        `json:"error,omitempty"`
	Took      time.Duration `json:"took_us"`
}

// Stats keeps a ring of recent queries plus counters per minute for the
// last 24h. All in memory: restart and it's gone, which is the point for a
// home/office resolver - no query history piling up on disk.
type Stats struct {
	mu      sync.Mutex
	ring    []Entry
	next    int
	full    bool
	started time.Time

	Total, Blocked, Cached, Errors uint64
	minutes                        [1440]minute
	domains, blockedDomains        map[string]uint64
	clients                        map[string]uint64
}

type minute struct {
	stamp                 int64 // unix minute this slot belongs to
	total, blocked, cache uint32
	latencyUS             uint64
	forwarded             uint32
}

func NewStats(n int) *Stats {
	if n <= 0 {
		n = 5000
	}
	return &Stats{ring: make([]Entry, n), started: time.Now(),
		domains: map[string]uint64{}, blockedDomains: map[string]uint64{}, clients: map[string]uint64{}}
}

func (s *Stats) Record(e Entry) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.ring[s.next] = e
	s.next = (s.next + 1) % len(s.ring)
	if s.next == 0 {
		s.full = true
	}
	s.Total++
	m := &s.minutes[(e.Time.Unix()/60)%1440]
	if stamp := e.Time.Unix() / 60; m.stamp != stamp {
		*m = minute{stamp: stamp}
	}
	m.total++
	switch e.Result {
	case "blocked":
		s.Blocked++
		m.blocked++
		s.blockedDomains[e.Rule]++
	case "cached":
		s.Cached++
		m.cache++
	case "forwarded":
		m.forwarded++
		m.latencyUS += uint64(e.Took.Microseconds())
	case "error":
		s.Errors++
	}
	s.domains[e.Name]++
	s.clients[e.Client]++
	// keep the top-N maps from growing forever on a busy network
	if len(s.domains) > 50000 {
		s.domains = trim(s.domains, 10000)
	}
	if len(s.blockedDomains) > 20000 {
		s.blockedDomains = trim(s.blockedDomains, 5000)
	}
}

func trim(m map[string]uint64, keep int) map[string]uint64 {
	top := topN(m, keep)
	out := make(map[string]uint64, keep)
	for _, kv := range top {
		out[kv.Key] = kv.Count
	}
	return out
}

type KV struct {
	Key   string `json:"key"`
	Count uint64 `json:"count"`
}

func topN(m map[string]uint64, n int) []KV {
	out := make([]KV, 0, len(m))
	for k, v := range m {
		out = append(out, KV{k, v})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Count != out[j].Count {
			return out[i].Count > out[j].Count
		}
		return out[i].Key < out[j].Key
	})
	if len(out) > n {
		out = out[:n]
	}
	return out
}

type Summary struct {
	Uptime        string   `json:"uptime"`
	Total         uint64   `json:"total"`
	Blocked       uint64   `json:"blocked"`
	Cached        uint64   `json:"cached"`
	Errors        uint64   `json:"errors"`
	BlockedPct    float64  `json:"blocked_pct"`
	TopDomains    []KV     `json:"top_domains"`
	TopBlocked    []KV     `json:"top_blocked"`
	TopClients    []KV     `json:"top_clients"`
	PerMinute     []Minute `json:"per_minute"` // last 60 minutes, oldest first
	AvgUpstreamMS float64  `json:"avg_upstream_ms"`
}

type Minute struct {
	T          int64   `json:"t"`
	Total      uint32  `json:"total"`
	Blocked    uint32  `json:"blocked"`
	Cached     uint32  `json:"cached"`
	UpstreamMS float64 `json:"upstream_ms"`
}

func (s *Stats) Summary(now time.Time) Summary {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := Summary{Uptime: now.Sub(s.started).Truncate(time.Second).String(), Total: s.Total, Blocked: s.Blocked,
		Cached: s.Cached, Errors: s.Errors,
		TopDomains: topN(s.domains, 10), TopBlocked: topN(s.blockedDomains, 10), TopClients: topN(s.clients, 10)}
	if s.Total > 0 {
		out.BlockedPct = float64(s.Blocked) / float64(s.Total) * 100
	}
	var fwd, lat uint64
	cur := now.Unix() / 60
	for i := cur - 59; i <= cur; i++ {
		m := s.minutes[i%1440]
		row := Minute{T: i * 60}
		if m.stamp == i {
			row.Total, row.Blocked, row.Cached = m.total, m.blocked, m.cache
			if m.forwarded > 0 {
				row.UpstreamMS = float64(m.latencyUS) / float64(m.forwarded) / 1000
			}
			fwd += uint64(m.forwarded)
			lat += m.latencyUS
		}
		out.PerMinute = append(out.PerMinute, row)
	}
	if fwd > 0 {
		out.AvgUpstreamMS = float64(lat) / float64(fwd) / 1000
	}
	return out
}

// Recent returns up to n log entries, newest first, optionally filtered.
func (s *Stats) Recent(n int, match func(Entry) bool) []Entry {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []Entry
	size := s.next
	if s.full {
		size = len(s.ring)
	}
	for i := 0; i < size && len(out) < n; i++ {
		idx := (s.next - 1 - i + len(s.ring)) % len(s.ring)
		e := s.ring[idx]
		if match == nil || match(e) {
			out = append(out, e)
		}
	}
	return out
}
