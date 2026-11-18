// Package dns has just enough of RFC 1035 for a forwarding resolver:
// read the question, build blocked/error answers, and walk the resource
// records of an upstream answer to find (and rewrite) TTLs. Everything
// else is passed through untouched.
package dns

import (
	"encoding/binary"
	"errors"
	"net"
	"strings"
)

const (
	TypeA     = 1
	TypeNS    = 2
	TypeCNAME = 5
	TypeSOA   = 6
	TypePTR   = 12
	TypeMX    = 15
	TypeTXT   = 16
	TypeAAAA  = 28
	TypeSRV   = 33
	TypeHTTPS = 65
	TypeANY   = 255

	ClassIN = 1

	RcodeOK       = 0
	RcodeFormErr  = 1
	RcodeServFail = 2
	RcodeNXDomain = 3
	RcodeRefused  = 5
)

var TypeNames = map[uint16]string{TypeA: "A", TypeNS: "NS", TypeCNAME: "CNAME", TypeSOA: "SOA", TypePTR: "PTR",
	TypeMX: "MX", TypeTXT: "TXT", TypeAAAA: "AAAA", TypeSRV: "SRV", TypeHTTPS: "HTTPS", TypeANY: "ANY"}

func TypeName(t uint16) string {
	if n, ok := TypeNames[t]; ok {
		return n
	}
	return "TYPE" + itoa(int(t))
}

var ErrShort = errors.New("dns: message too short")
var ErrName = errors.New("dns: bad name")

type Question struct {
	Name  string // lower case, no trailing dot
	Type  uint16
	Class uint16
}

// Message is a parsed view over a raw packet. Raw is kept so the message can
// be forwarded or cached as-is.
type Message struct {
	Raw      []byte
	ID       uint16
	Flags    uint16
	Question Question
	QDCount  uint16
	ANCount  uint16
	NSCount  uint16
	ARCount  uint16
	qEnd     int // offset just past the question section
}

func (m *Message) Response() bool { return m.Flags&0x8000 != 0 }
func (m *Message) Rcode() int     { return int(m.Flags & 0x000f) }

// Parse reads the header and the first question.
func Parse(b []byte) (*Message, error) {
	if len(b) < 12 {
		return nil, ErrShort
	}
	m := &Message{Raw: b,
		ID: binary.BigEndian.Uint16(b), Flags: binary.BigEndian.Uint16(b[2:]),
		QDCount: binary.BigEndian.Uint16(b[4:]), ANCount: binary.BigEndian.Uint16(b[6:]),
		NSCount: binary.BigEndian.Uint16(b[8:]), ARCount: binary.BigEndian.Uint16(b[10:])}
	if m.QDCount == 0 {
		m.qEnd = 12
		return m, nil
	}
	name, off, err := readName(b, 12)
	if err != nil {
		return nil, err
	}
	if off+4 > len(b) {
		return nil, ErrShort
	}
	m.Question = Question{Name: name, Type: binary.BigEndian.Uint16(b[off:]), Class: binary.BigEndian.Uint16(b[off+2:])}
	m.qEnd = off + 4
	return m, nil
}

func readName(b []byte, off int) (string, int, error) {
	var labels []string
	next := -1
	for jumps := 0; ; {
		if off >= len(b) {
			return "", 0, ErrShort
		}
		l := int(b[off])
		switch {
		case l == 0:
			if next < 0 {
				next = off + 1
			}
			return strings.ToLower(strings.Join(labels, ".")), next, nil
		case l&0xc0 == 0xc0:
			if off+1 >= len(b) {
				return "", 0, ErrShort
			}
			if next < 0 {
				next = off + 2
			}
			jumps++
			if jumps > 20 {
				return "", 0, ErrName // pointer loop
			}
			off = int(binary.BigEndian.Uint16(b[off:]) & 0x3fff)
		default:
			if off+1+l > len(b) || l > 63 {
				return "", 0, ErrName
			}
			labels = append(labels, string(b[off+1:off+1+l]))
			off += 1 + l
		}
	}
}

func skipName(b []byte, off int) (int, error) {
	for {
		if off >= len(b) {
			return 0, ErrShort
		}
		l := int(b[off])
		switch {
		case l == 0:
			return off + 1, nil
		case l&0xc0 == 0xc0:
			return off + 2, nil
		default:
			off += 1 + l
		}
	}
}

// WalkRR calls fn with the offset of every answer/authority/additional RR's
// TTL field (except OPT pseudo-records, whose "TTL" isn't one).
func (m *Message) WalkRR(fn func(ttlOff int, rrType uint16)) error {
	b := m.Raw
	off := m.qEnd
	// any further questions (almost never more than one)
	for i := 1; i < int(m.QDCount); i++ {
		o, err := skipName(b, off)
		if err != nil {
			return err
		}
		off = o + 4
	}
	total := int(m.ANCount) + int(m.NSCount) + int(m.ARCount)
	for i := 0; i < total; i++ {
		o, err := skipName(b, off)
		if err != nil {
			return err
		}
		if o+10 > len(b) {
			return ErrShort
		}
		t := binary.BigEndian.Uint16(b[o:])
		rdlen := int(binary.BigEndian.Uint16(b[o+8:]))
		if t != 41 { // OPT
			fn(o+4, t)
		}
		off = o + 10 + rdlen
		if off > len(b) {
			return ErrShort
		}
	}
	return nil
}

// MinTTL is the smallest TTL in the answer, used as the cache lifetime.
// Negative answers (NXDOMAIN / NODATA) use the SOA minimum if present.
func (m *Message) MinTTL() (uint32, bool) {
	min := uint32(0)
	found := false
	_ = m.WalkRR(func(o int, _ uint16) {
		ttl := binary.BigEndian.Uint32(m.Raw[o:])
		if !found || ttl < min {
			min, found = ttl, true
		}
	})
	return min, found
}

// SetTTLs rewrites every TTL (used when serving from cache so clients see
// the remaining lifetime, not the original one).
func SetTTLs(b []byte, m *Message, ttl uint32) {
	_ = m.WalkRR(func(o int, _ uint16) { binary.BigEndian.PutUint32(b[o:], ttl) })
}

// Answers returns the A/AAAA/CNAME data in an answer, for the query log.
func (m *Message) Answers() []string {
	b := m.Raw
	var out []string
	off := m.qEnd
	for i := 0; i < int(m.ANCount); i++ {
		o, err := skipName(b, off)
		if err != nil || o+10 > len(b) {
			return out
		}
		t := binary.BigEndian.Uint16(b[o:])
		rdlen := int(binary.BigEndian.Uint16(b[o+8:]))
		rd := o + 10
		if rd+rdlen > len(b) {
			return out
		}
		switch {
		case t == TypeA && rdlen == 4:
			out = append(out, net.IP(b[rd:rd+4]).String())
		case t == TypeAAAA && rdlen == 16:
			out = append(out, net.IP(b[rd:rd+16]).String())
		case t == TypeCNAME:
			if n, _, err := readName(b, rd); err == nil {
				out = append(out, n)
			}
		}
		off = rd + rdlen
	}
	return out
}

// Reply builds an answer to q from scratch. For a blocked A/AAAA question
// with sinkhole=true it answers 0.0.0.0 / :: (fewer client retries than
// NXDOMAIN); otherwise it's just the rcode.
func Reply(q *Message, rcode int, sinkhole bool, ttl uint32) []byte {
	qsec := q.Raw[12:q.qEnd]
	out := make([]byte, 12, 12+len(qsec)+28)
	binary.BigEndian.PutUint16(out[0:], q.ID)
	// QR=1, opcode copied, RD copied, RA=1
	flags := uint16(0x8000) | (q.Flags & 0x7900) | 0x0080 | uint16(rcode&0xf)
	binary.BigEndian.PutUint16(out[2:], flags)
	binary.BigEndian.PutUint16(out[4:], q.QDCount)
	out = append(out, qsec...)
	if sinkhole && rcode == RcodeOK && (q.Question.Type == TypeA || q.Question.Type == TypeAAAA) {
		binary.BigEndian.PutUint16(out[6:], 1)
		rr := []byte{0xc0, 0x0c, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0}
		binary.BigEndian.PutUint16(rr[2:], q.Question.Type)
		binary.BigEndian.PutUint32(rr[6:], ttl)
		if q.Question.Type == TypeA {
			binary.BigEndian.PutUint16(rr[10:], 4)
			rr = append(rr, 0, 0, 0, 0)
		} else {
			binary.BigEndian.PutUint16(rr[10:], 16)
			rr = append(rr, make([]byte, 16)...)
		}
		out = append(out, rr...)
	}
	return out
}

// Query builds a simple recursive query, used by tests and the health check.
func Query(id uint16, name string, qtype uint16) []byte {
	b := make([]byte, 12, 64)
	binary.BigEndian.PutUint16(b[0:], id)
	binary.BigEndian.PutUint16(b[2:], 0x0100) // RD
	binary.BigEndian.PutUint16(b[4:], 1)
	for _, l := range strings.Split(strings.TrimSuffix(name, "."), ".") {
		b = append(b, byte(len(l)))
		b = append(b, l...)
	}
	b = append(b, 0, 0, 0, 0, 0)
	binary.BigEndian.PutUint16(b[len(b)-4:], qtype)
	binary.BigEndian.PutUint16(b[len(b)-2:], ClassIN)
	return b
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var buf [12]byte
	i := len(buf)
	neg := n < 0
	if neg {
		n = -n
	}
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		i--
		buf[i] = '-'
	}
	return string(buf[i:])
}
