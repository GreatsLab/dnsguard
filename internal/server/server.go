// Package server is the resolver: listen, check the blocklist, answer from
// cache or forward upstream, keep stats.
package server

import (
	"context"
	"encoding/binary"
	"errors"
	"io"
	"log/slog"
	"net"
	"strconv"
	"sync"
	"time"

	"github.com/GreatsLab/dnsguard/internal/block"
	"github.com/GreatsLab/dnsguard/internal/cache"
	"github.com/GreatsLab/dnsguard/internal/dns"
)

type Config struct {
	Listen      string // ":53"
	Upstreams   []Upstream
	Block       *block.List
	CacheSize   int
	Sinkhole    bool // answer 0.0.0.0 instead of NXDOMAIN
	BlockTTL    uint32
	MinTTL      time.Duration // floor for cached answers
	MaxTTL      time.Duration
	NegativeTTL time.Duration // NXDOMAIN cache time when there's no SOA
	LogSize     int
	Log         *slog.Logger
}

type Server struct {
	cfg   Config
	pool  *pool
	cache *cache.Cache
	Stats *Stats

	mu       sync.Mutex
	udp      net.PacketConn
	tcp      net.Listener
	inflight map[string]*call // collapse identical concurrent upstream queries
}

type call struct {
	done chan struct{}
	resp []byte
	via  string
	err  error
}

func New(cfg Config) *Server {
	if cfg.Log == nil {
		cfg.Log = slog.New(slog.NewTextHandler(io.Discard, nil))
	}
	if cfg.BlockTTL == 0 {
		cfg.BlockTTL = 60
	}
	if cfg.MaxTTL == 0 {
		cfg.MaxTTL = 24 * time.Hour
	}
	if cfg.NegativeTTL == 0 {
		cfg.NegativeTTL = 60 * time.Second
	}
	return &Server{cfg: cfg, pool: NewPool(cfg.Upstreams), cache: cache.New(cfg.CacheSize),
		Stats: NewStats(cfg.LogSize), inflight: map[string]*call{}}
}

func (s *Server) Cache() *cache.Cache { return s.cache }
func (s *Server) Block() *block.List  { return s.cfg.Block }

// Start binds UDP and TCP on cfg.Listen. Returns the bound address (useful
// with ":0" in tests).
func (s *Server) Start(ctx context.Context) (string, error) {
	pc, err := net.ListenPacket("udp", s.cfg.Listen)
	if err != nil {
		return "", err
	}
	addr := pc.LocalAddr().String()
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		pc.Close()
		return "", err
	}
	s.mu.Lock()
	s.udp, s.tcp = pc, ln
	s.mu.Unlock()
	go s.serveUDP(ctx, pc)
	go s.serveTCP(ctx, ln)
	go func() { <-ctx.Done(); pc.Close(); ln.Close() }()
	return addr, nil
}

func (s *Server) serveUDP(ctx context.Context, pc net.PacketConn) {
	buf := make([]byte, 4096)
	for {
		n, from, err := pc.ReadFrom(buf)
		if err != nil {
			if ctx.Err() != nil || errors.Is(err, net.ErrClosed) {
				return
			}
			continue
		}
		q := append([]byte(nil), buf[:n]...)
		go func() {
			resp := s.Handle(ctx, q, clientIP(from), "udp")
			if resp == nil {
				return
			}
			// keep UDP answers under 1232 bytes (DNS flag day 2020) unless the
			// client said it can take more; otherwise set TC and let it retry on TCP
			if len(resp) > maxUDP(q) {
				resp = truncate(resp)
			}
			pc.WriteTo(resp, from)
		}()
	}
}

func (s *Server) serveTCP(ctx context.Context, ln net.Listener) {
	for {
		c, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil || errors.Is(err, net.ErrClosed) {
				return
			}
			continue
		}
		go func() {
			defer c.Close()
			for {
				c.SetDeadline(time.Now().Add(10 * time.Second))
				var l [2]byte
				if _, err := io.ReadFull(c, l[:]); err != nil {
					return
				}
				q := make([]byte, binary.BigEndian.Uint16(l[:]))
				if _, err := io.ReadFull(c, q); err != nil {
					return
				}
				resp := s.Handle(ctx, q, clientIP(c.RemoteAddr()), "tcp")
				if resp == nil {
					return
				}
				out := make([]byte, 2+len(resp))
				binary.BigEndian.PutUint16(out, uint16(len(resp)))
				copy(out[2:], resp)
				if _, err := c.Write(out); err != nil {
					return
				}
			}
		}()
	}
}

// Handle answers one query. Exported so the DoH endpoint and tests can use it.
func (s *Server) Handle(ctx context.Context, raw []byte, client, transport string) []byte {
	start := time.Now()
	q, err := dns.Parse(raw)
	if err != nil || q.Response() || q.QDCount != 1 {
		if len(raw) >= 12 && err == nil {
			return dns.Reply(q, dns.RcodeFormErr, false, 0)
		}
		return nil // too broken to even answer
	}
	e := Entry{Time: start, Client: client, Name: q.Question.Name, Type: dns.TypeName(q.Question.Type), Transport: transport}
	defer func() { e.Took = time.Since(start); s.Stats.Record(e) }()

	if blocked, rule := s.cfg.Block.Match(q.Question.Name); blocked {
		e.Result, e.Rule = "blocked", rule
		return dns.Reply(q, dns.RcodeOK, s.cfg.Sinkhole, s.cfg.BlockTTL)
	}

	key := q.Question.Name + "|" + strconv.Itoa(int(q.Question.Type)) + "|" + strconv.Itoa(int(q.Question.Class)) +
		"|" + strconv.FormatBool(q.Flags&0x0010 != 0) // CD bit changes the answer
	if msg, left, ok := s.cache.Get(key); ok {
		binary.BigEndian.PutUint16(msg, q.ID)
		if m, err := dns.Parse(msg); err == nil {
			dns.SetTTLs(msg, m, left)
			e.Answers = m.Answers()
			e.Rcode = m.Rcode()
		}
		e.Result = "cached"
		return msg
	}

	resp, via, err := s.forward(ctx, key, raw)
	if err != nil {
		e.Result, e.Error = "error", err.Error()
		return dns.Reply(q, dns.RcodeServFail, false, 0)
	}
	binary.BigEndian.PutUint16(resp, q.ID)
	e.Result, e.Upstream = "forwarded", via
	if m, err := dns.Parse(resp); err == nil {
		e.Answers, e.Rcode = m.Answers(), m.Rcode()
		s.store(key, resp, m)
	}
	return resp
}

// forward sends to upstream, but if the same question is already in flight
// (a page load fires the same lookup from ten tabs) wait for that answer
// instead of asking again.
func (s *Server) forward(ctx context.Context, key string, raw []byte) ([]byte, string, error) {
	s.mu.Lock()
	if c, ok := s.inflight[key]; ok {
		s.mu.Unlock()
		select {
		case <-c.done:
			if c.err != nil {
				return nil, "", c.err
			}
			return append([]byte(nil), c.resp...), c.via + " (shared)", nil
		case <-ctx.Done():
			return nil, "", ctx.Err()
		}
	}
	c := &call{done: make(chan struct{})}
	s.inflight[key] = c
	s.mu.Unlock()

	c.resp, c.via, c.err = s.pool.Exchange(ctx, raw)

	s.mu.Lock()
	delete(s.inflight, key)
	s.mu.Unlock()
	close(c.done)
	if c.err != nil {
		return nil, "", c.err
	}
	return append([]byte(nil), c.resp...), c.via, nil
}

func (s *Server) store(key string, resp []byte, m *dns.Message) {
	rcode := m.Rcode()
	if rcode != dns.RcodeOK && rcode != dns.RcodeNXDomain {
		return // never cache SERVFAIL/REFUSED
	}
	if resp[2]&0x02 != 0 {
		return // truncated
	}
	var ttl time.Duration
	if t, ok := m.MinTTL(); ok {
		ttl = time.Duration(t) * time.Second
	} else {
		ttl = s.cfg.NegativeTTL // NXDOMAIN/NODATA without SOA
	}
	if ttl < s.cfg.MinTTL {
		ttl = s.cfg.MinTTL
	}
	if ttl > s.cfg.MaxTTL {
		ttl = s.cfg.MaxTTL
	}
	s.cache.Set(key, resp, ttl)
}

func clientIP(a net.Addr) string {
	if h, _, err := net.SplitHostPort(a.String()); err == nil {
		return h
	}
	return a.String()
}

// EDNS0 OPT record in the additional section advertises the client's UDP size.
func maxUDP(q []byte) int {
	m, err := dns.Parse(q)
	if err != nil || m.ARCount == 0 {
		return 512
	}
	size := 512
	// the OPT RR is: root name (0), type 41, class = UDP size. It's almost
	// always the last record of a query, so scan from the end.
	for i := len(q) - 11; i >= 12; i-- {
		if q[i] == 0 && q[i+1] == 0 && q[i+2] == 41 {
			size = int(binary.BigEndian.Uint16(q[i+3:]))
			break
		}
	}
	if size < 512 {
		size = 512
	}
	if size > 1232 {
		size = 1232
	}
	return size
}

// truncate keeps the header + question and sets TC.
func truncate(resp []byte) []byte {
	m, err := dns.Parse(resp)
	if err != nil {
		return resp[:12]
	}
	out := dns.Reply(m, m.Rcode(), false, 0)
	out[2] |= 0x02
	return out
}
