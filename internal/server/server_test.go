package server

import (
	"bytes"
	"context"
	"encoding/binary"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"testing/fstest"
	"time"

	"github.com/GreatsLab/dnsguard/internal/block"
	"github.com/GreatsLab/dnsguard/internal/dns"
)

// fakeUpstream answers every A query with 192.0.2.<n> (n = query count), TTL 300,
// and NXDOMAIN for names under .invalid
type fakeUpstream struct {
	addr  string
	count atomic.Int32
	delay time.Duration
}

func startFake(t *testing.T, delay time.Duration) *fakeUpstream {
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	f := &fakeUpstream{addr: pc.LocalAddr().String(), delay: delay}
	t.Cleanup(func() { pc.Close() })
	go func() {
		buf := make([]byte, 2048)
		for {
			n, from, err := pc.ReadFrom(buf)
			if err != nil {
				return
			}
			q := append([]byte(nil), buf[:n]...)
			c := f.count.Add(1)
			go func() {
				time.Sleep(f.delay)
				pc.WriteTo(fakeAnswer(q, byte(c)), from)
			}()
		}
	}()
	return f
}

func fakeAnswer(q []byte, last byte) []byte {
	m, _ := dns.Parse(q)
	r := append([]byte(nil), q[:12]...)
	r = append(r, q[12:]...)
	r[2] |= 0x80
	r[3] = 0x80
	if bytes.HasSuffix([]byte(m.Question.Name), []byte(".invalid")) {
		r[3] |= dns.RcodeNXDomain
		return r
	}
	binary.BigEndian.PutUint16(r[6:], 1)
	rr := []byte{0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 1, 0x2c, 0, 4, 192, 0, 2, last}
	return append(r, rr...)
}

func newServer(t *testing.T, ups ...Upstream) (*Server, string) {
	l := block.New()
	l.Replace(map[string]struct{}{"ads.example": {}})
	s := New(Config{Listen: "127.0.0.1:0", Upstreams: ups, Block: l, CacheSize: 100, Sinkhole: true})
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	addr, err := s.Start(ctx)
	if err != nil {
		t.Fatal(err)
	}
	return s, addr
}

func ask(t *testing.T, network, addr, name string, qt uint16) *dns.Message {
	t.Helper()
	c, err := net.DialTimeout(network, addr, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(3 * time.Second))
	q := dns.Query(0xbeef, name, qt)
	var r []byte
	if network == "udp" {
		c.Write(q)
		buf := make([]byte, 4096)
		n, err := c.Read(buf)
		if err != nil {
			t.Fatal(err)
		}
		r = buf[:n]
	} else {
		r, err = streamExchange(context.Background(), c, q)
		if err != nil {
			t.Fatal(err)
		}
	}
	m, err := dns.Parse(r)
	if err != nil {
		t.Fatal(err)
	}
	if m.ID != 0xbeef {
		t.Fatalf("id %x", m.ID)
	}
	return m
}

func TestBlockForwardCache(t *testing.T) {
	f := startFake(t, 0)
	up, _ := ParseUpstream(f.addr)
	s, addr := newServer(t, up)

	if a := ask(t, "udp", addr, "tracker.ads.example", dns.TypeA).Answers(); len(a) != 1 || a[0] != "0.0.0.0" {
		t.Fatalf("blocked answer %v", a)
	}
	if f.count.Load() != 0 {
		t.Fatal("blocked name went upstream")
	}
	first := ask(t, "udp", addr, "github.com", dns.TypeA).Answers()
	second := ask(t, "tcp", addr, "github.com", dns.TypeA).Answers()
	if first[0] != "192.0.2.1" || second[0] != "192.0.2.1" || f.count.Load() != 1 {
		t.Fatalf("cache: %v %v upstream=%d", first, second, f.count.Load())
	}
	if nx := ask(t, "udp", addr, "nope.invalid", dns.TypeA); nx.Rcode() != dns.RcodeNXDomain {
		t.Fatal("nxdomain not passed through")
	}
	sum := s.Stats.Summary(time.Now())
	if sum.Total != 4 || sum.Blocked != 1 || sum.Cached != 1 {
		t.Fatalf("%+v", sum)
	}
}

func TestCachedTTLCountsDown(t *testing.T) {
	f := startFake(t, 0)
	up, _ := ParseUpstream(f.addr)
	s, addr := newServer(t, up)
	ask(t, "udp", addr, "ttl.example", dns.TypeA)
	now := time.Now().Add(100 * time.Second)
	s.cache.SetClock(func() time.Time { return now })
	m := ask(t, "udp", addr, "ttl.example", dns.TypeA)
	ttl, _ := m.MinTTL()
	if ttl < 195 || ttl > 200 {
		t.Fatalf("ttl %d, want ~200", ttl)
	}
}

func TestConcurrentQueriesCollapse(t *testing.T) {
	f := startFake(t, 150*time.Millisecond)
	up, _ := ParseUpstream(f.addr)
	_, addr := newServer(t, up)
	done := make(chan struct{})
	for i := 0; i < 10; i++ {
		go func() { ask(t, "udp", addr, "popular.example", dns.TypeA); done <- struct{}{} }()
	}
	for i := 0; i < 10; i++ {
		<-done
	}
	if n := f.count.Load(); n != 1 {
		t.Fatalf("upstream asked %d times, want 1", n)
	}
}

func TestFailoverToSecondUpstream(t *testing.T) {
	dead, _ := ParseUpstream("127.0.0.1:1") // nothing listening
	f := startFake(t, 0)
	good, _ := ParseUpstream(f.addr)
	_, addr := newServer(t, dead, good)
	if a := ask(t, "udp", addr, "failover.example", dns.TypeA).Answers(); len(a) != 1 {
		t.Fatal("no answer via second upstream")
	}
}

func TestDoHUpstreamAndEndpoint(t *testing.T) {
	// upstream DoH server that checks RFC 8484 basics
	var sawID uint16 = 1
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Content-Type") != "application/dns-message" {
			http.Error(w, "ct", 415)
			return
		}
		q, _ := io.ReadAll(r.Body)
		sawID = binary.BigEndian.Uint16(q)
		w.Header().Set("Content-Type", "application/dns-message")
		w.Write(fakeAnswer(q, 7))
	}))
	defer ts.Close()
	up, _ := ParseUpstream(ts.URL + "/dns-query")
	s, addr := newServer(t, up)
	if a := ask(t, "udp", addr, "doh.example", dns.TypeA).Answers(); a[0] != "192.0.2.7" {
		t.Fatal(a)
	}
	if sawID != 0 {
		t.Fatal("DoH query should use ID 0")
	}

	// and our own /dns-query endpoint
	h := s.HTTP(fstest.MapFS{"index.html": {Data: []byte("hi")}}, "")
	rec := httptest.NewRecorder()
	req := httptest.NewRequest("POST", "/dns-query", bytes.NewReader(dns.Query(77, "ads.example", dns.TypeA)))
	req.Header.Set("Content-Type", "application/dns-message")
	h.ServeHTTP(rec, req)
	m, err := dns.Parse(rec.Body.Bytes())
	if err != nil || m.ID != 77 || m.Answers()[0] != "0.0.0.0" {
		t.Fatalf("doh endpoint: %v %v", err, rec.Body.Bytes())
	}
}

func TestAPIToken(t *testing.T) {
	f := startFake(t, 0)
	up, _ := ParseUpstream(f.addr)
	s, _ := newServer(t, up)
	h := s.HTTP(fstest.MapFS{"index.html": {Data: []byte("hi")}}, "s3cret")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest("GET", "/api/summary", nil))
	if rec.Code != 401 {
		t.Fatal("api open without token")
	}
	rec = httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/api/summary", nil)
	req.Header.Set("Authorization", "Bearer s3cret")
	h.ServeHTTP(rec, req)
	if rec.Code != 200 {
		t.Fatal(rec.Code)
	}
}
