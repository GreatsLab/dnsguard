package server

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync/atomic"
	"time"
)

// Upstream forwards a raw DNS query and returns the raw answer.
type Upstream interface {
	Exchange(ctx context.Context, q []byte) ([]byte, error)
	String() string
}

// ParseUpstream understands:
//
//	1.1.1.1            plain DNS, UDP with TCP fallback on truncation
//	1.1.1.1:5353
//	udp://9.9.9.9:53
//	tcp://9.9.9.9:53
//	tls://1.1.1.1      DNS-over-TLS (853), SNI taken from #name: tls://1.1.1.1#one.one.one.one
//	https://cloudflare-dns.com/dns-query   DNS-over-HTTPS (RFC 8484)
//	http://127.0.0.1:8080/dns-query        plain-HTTP DoH, for a local proxy only
func ParseUpstream(s string) (Upstream, error) {
	switch {
	case strings.HasPrefix(s, "https://"), strings.HasPrefix(s, "http://"):
		u, err := url.Parse(s)
		if err != nil {
			return nil, err
		}
		return &doh{url: u.String(), client: &http.Client{
			Timeout:   5 * time.Second,
			Transport: &http.Transport{ForceAttemptHTTP2: true, MaxIdleConnsPerHost: 8, IdleConnTimeout: 90 * time.Second},
		}}, nil
	case strings.HasPrefix(s, "tls://"):
		rest := strings.TrimPrefix(s, "tls://")
		host, name, _ := strings.Cut(rest, "#")
		addr := withPort(host, "853")
		if name == "" {
			name, _, _ = net.SplitHostPort(addr)
		}
		return &dot{addr: addr, name: name}, nil
	case strings.HasPrefix(s, "tcp://"):
		return &plain{addr: withPort(strings.TrimPrefix(s, "tcp://"), "53"), tcpOnly: true}, nil
	default:
		s = strings.TrimPrefix(s, "udp://")
		if s == "" {
			return nil, errors.New("empty upstream")
		}
		return &plain{addr: withPort(s, "53")}, nil
	}
}

func withPort(h, port string) string {
	if _, _, err := net.SplitHostPort(h); err == nil {
		return h
	}
	return net.JoinHostPort(strings.Trim(h, "[]"), port)
}

// ---- plain UDP/TCP -----------------------------------------------------

type plain struct {
	addr    string
	tcpOnly bool
}

func (p *plain) String() string {
	if p.tcpOnly {
		return "tcp://" + p.addr
	}
	return p.addr
}

func (p *plain) Exchange(ctx context.Context, q []byte) ([]byte, error) {
	if !p.tcpOnly {
		r, err := udpExchange(ctx, p.addr, q)
		if err != nil {
			return nil, err
		}
		// TC bit: answer didn't fit in UDP, ask again over TCP
		if len(r) >= 3 && r[2]&0x02 == 0 {
			return r, nil
		}
	}
	var d net.Dialer
	c, err := d.DialContext(ctx, "tcp", p.addr)
	if err != nil {
		return nil, err
	}
	defer c.Close()
	return streamExchange(ctx, c, q)
}

func udpExchange(ctx context.Context, addr string, q []byte) ([]byte, error) {
	var d net.Dialer
	c, err := d.DialContext(ctx, "udp", addr)
	if err != nil {
		return nil, err
	}
	defer c.Close()
	if dl, ok := ctx.Deadline(); ok {
		c.SetDeadline(dl)
	}
	if _, err := c.Write(q); err != nil {
		return nil, err
	}
	buf := make([]byte, 4096)
	for {
		n, err := c.Read(buf)
		if err != nil {
			return nil, err
		}
		// ignore stray packets with the wrong ID (spoofing attempts, late answers)
		if n >= 2 && buf[0] == q[0] && buf[1] == q[1] {
			return append([]byte(nil), buf[:n]...), nil
		}
	}
}

func streamExchange(ctx context.Context, c net.Conn, q []byte) ([]byte, error) {
	if dl, ok := ctx.Deadline(); ok {
		c.SetDeadline(dl)
	}
	msg := make([]byte, 2+len(q))
	binary.BigEndian.PutUint16(msg, uint16(len(q)))
	copy(msg[2:], q)
	if _, err := c.Write(msg); err != nil {
		return nil, err
	}
	var l [2]byte
	if _, err := io.ReadFull(c, l[:]); err != nil {
		return nil, err
	}
	r := make([]byte, binary.BigEndian.Uint16(l[:]))
	if _, err := io.ReadFull(c, r); err != nil {
		return nil, err
	}
	return r, nil
}

// ---- DNS over TLS ------------------------------------------------------

type dot struct{ addr, name string }

func (d *dot) String() string { return "tls://" + d.addr }

func (d *dot) Exchange(ctx context.Context, q []byte) ([]byte, error) {
	td := &tls.Dialer{Config: &tls.Config{ServerName: d.name, MinVersion: tls.VersionTLS12}}
	c, err := td.DialContext(ctx, "tcp", d.addr)
	if err != nil {
		return nil, err
	}
	defer c.Close()
	return streamExchange(ctx, c, q)
}

// ---- DNS over HTTPS ----------------------------------------------------

type doh struct {
	url    string
	client *http.Client
}

func (d *doh) String() string { return d.url }

func (d *doh) Exchange(ctx context.Context, q []byte) ([]byte, error) {
	// RFC 8484 says use ID 0 for cacheability; put the real one back after
	id0, id1 := q[0], q[1]
	body := append([]byte(nil), q...)
	body[0], body[1] = 0, 0
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, d.url, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/dns-message")
	req.Header.Set("Accept", "application/dns-message")
	resp, err := d.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("doh: %s", resp.Status)
	}
	r, err := io.ReadAll(io.LimitReader(resp.Body, 65535))
	if err != nil {
		return nil, err
	}
	if len(r) < 12 {
		return nil, errors.New("doh: short answer")
	}
	r[0], r[1] = id0, id1
	return r, nil
}

// ---- pool: try upstreams in order of who's been fastest lately ------------

type pool struct {
	ups  []Upstream
	rtt  []atomic.Int64 // EWMA in microseconds
	fail []atomic.Int64
}

func NewPool(ups []Upstream) *pool {
	return &pool{ups: ups, rtt: make([]atomic.Int64, len(ups)), fail: make([]atomic.Int64, len(ups))}
}

func (p *pool) order() []int {
	idx := make([]int, len(p.ups))
	for i := range idx {
		idx[i] = i
	}
	score := func(i int) int64 { return p.rtt[i].Load() + p.fail[i].Load()*200000 }
	for i := 1; i < len(idx); i++ {
		for j := i; j > 0 && score(idx[j]) < score(idx[j-1]); j-- {
			idx[j], idx[j-1] = idx[j-1], idx[j]
		}
	}
	return idx
}

func (p *pool) Exchange(ctx context.Context, q []byte) ([]byte, string, error) {
	var lastErr error
	for _, i := range p.order() {
		start := time.Now()
		c, cancel := context.WithTimeout(ctx, 2500*time.Millisecond)
		r, err := p.ups[i].Exchange(c, q)
		cancel()
		if err == nil {
			us := time.Since(start).Microseconds()
			old := p.rtt[i].Load()
			if old == 0 {
				p.rtt[i].Store(us)
			} else {
				p.rtt[i].Store((old*7 + us) / 8)
			}
			if f := p.fail[i].Load(); f > 0 {
				p.fail[i].Store(f - 1)
			}
			return r, p.ups[i].String(), nil
		}
		p.fail[i].Add(1)
		lastErr = err
		if ctx.Err() != nil {
			break
		}
	}
	return nil, "", lastErr
}

type UpstreamStatus struct {
	Name     string  `json:"name"`
	RTTms    float64 `json:"rtt_ms"`
	Failures int64   `json:"recent_failures"`
}

func (p *pool) Status() []UpstreamStatus {
	out := make([]UpstreamStatus, len(p.ups))
	for i, u := range p.ups {
		out[i] = UpstreamStatus{Name: u.String(), RTTms: float64(p.rtt[i].Load()) / 1000, Failures: p.fail[i].Load()}
	}
	return out
}
