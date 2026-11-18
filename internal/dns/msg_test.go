package dns

import (
	"encoding/binary"
	"testing"
)

// answer builds a response to q with one A record and the given TTL
func answer(q []byte, ip [4]byte, ttl uint32) []byte {
	r := append([]byte(nil), q...)
	r[2] |= 0x80
	r[3] |= 0x80
	binary.BigEndian.PutUint16(r[6:], 1)
	rr := []byte{0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 0, 0, 0, 4, ip[0], ip[1], ip[2], ip[3]}
	binary.BigEndian.PutUint32(rr[6:], ttl)
	return append(r, rr...)
}

func TestParseQuery(t *testing.T) {
	q := Query(0x1234, "WWW.Example.COM.", TypeAAAA)
	m, err := Parse(q)
	if err != nil {
		t.Fatal(err)
	}
	if m.ID != 0x1234 || m.Question.Name != "www.example.com" || m.Question.Type != TypeAAAA || m.Response() {
		t.Fatalf("%+v", m)
	}
}

func TestTTLs(t *testing.T) {
	r := answer(Query(1, "a.example", TypeA), [4]byte{192, 0, 2, 1}, 300)
	m, err := Parse(r)
	if err != nil {
		t.Fatal(err)
	}
	if ttl, ok := m.MinTTL(); !ok || ttl != 300 {
		t.Fatal(ttl, ok)
	}
	SetTTLs(r, m, 42)
	if ttl, _ := m.MinTTL(); ttl != 42 {
		t.Fatal(ttl)
	}
	if a := m.Answers(); len(a) != 1 || a[0] != "192.0.2.1" {
		t.Fatal(a)
	}
}

func TestReplySinkhole(t *testing.T) {
	q, _ := Parse(Query(9, "ads.example", TypeA))
	r, err := Parse(Reply(q, RcodeOK, true, 60))
	if err != nil {
		t.Fatal(err)
	}
	if r.ID != 9 || !r.Response() || r.ANCount != 1 || r.Answers()[0] != "0.0.0.0" {
		t.Fatalf("%+v %v", r, r.Answers())
	}
	nx, _ := Parse(Reply(q, RcodeNXDomain, true, 60))
	if nx.Rcode() != RcodeNXDomain || nx.ANCount != 0 {
		t.Fatal("nxdomain")
	}
	q6, _ := Parse(Query(9, "ads.example", TypeAAAA))
	r6, _ := Parse(Reply(q6, RcodeOK, true, 60))
	if r6.Answers()[0] != "::" {
		t.Fatal(r6.Answers())
	}
}

func TestMalformed(t *testing.T) {
	for _, b := range [][]byte{
		{},
		make([]byte, 11),
		// pointer to itself
		{0, 1, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0xc0, 12, 0, 1, 0, 1},
		// label runs off the end
		{0, 1, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 40, 'a'},
	} {
		if _, err := Parse(b); err == nil {
			t.Errorf("expected error for %v", b)
		}
	}
}
