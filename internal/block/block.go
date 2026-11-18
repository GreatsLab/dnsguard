// Package block holds the blocklist: domains that get sinkholed, plus an
// allowlist that wins over it. Blocking a domain blocks every subdomain,
// so "doubleclick.net" also covers "ad.doubleclick.net".
package block

import (
	"bufio"
	"io"
	"net"
	"strings"
	"sync"
	"sync/atomic"
)

type set map[string]struct{}

// List is safe for concurrent use; Replace swaps the whole set atomically so
// a refresh never leaves a half-loaded list in place.
type List struct {
	blocked atomic.Pointer[set]
	mu      sync.Mutex
	allow   set
}

func New() *List {
	l := &List{allow: set{}}
	empty := set{}
	l.blocked.Store(&empty)
	return l
}

func (l *List) Len() int { return len(*l.blocked.Load()) }

func (l *List) Replace(domains map[string]struct{}) {
	s := set(domains)
	l.blocked.Store(&s)
}

func (l *List) Allow(domains ...string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	for _, d := range domains {
		if d = clean(d); d != "" {
			l.allow[d] = struct{}{}
		}
	}
}

// Match reports whether name is blocked, and by which list entry.
// Walks from the full name up to the TLD: a.b.example.com, b.example.com,
// example.com, com. Allowlist entries are checked at each level first, so
// allowing "cdn.example.com" un-blocks it even if "example.com" is blocked.
func (l *List) Match(name string) (bool, string) {
	name = normalise(name)
	b := *l.blocked.Load()
	l.mu.Lock()
	allow := l.allow
	l.mu.Unlock()
	for n := name; n != ""; {
		if _, ok := allow[n]; ok {
			return false, ""
		}
		if _, ok := b[n]; ok {
			return true, n
		}
		i := strings.IndexByte(n, '.')
		if i < 0 {
			break
		}
		n = n[i+1:]
	}
	return false, ""
}

// Parse reads a blocklist in any of the usual formats into dst:
//
//	0.0.0.0 ads.example.com        hosts file (any IP, multiple names ok)
//	ads.example.com                plain domain list
//	||ads.example.com^             adblock-style domain rules
//	*.ads.example.com              wildcard (same as the plain domain)
//
// Comments (#, !) and anything that isn't a hostname are skipped. Returns
// how many entries were added.
func Parse(r io.Reader, dst map[string]struct{}) (int, error) {
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 64*1024), 1024*1024)
	n := 0
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || line[0] == '#' || line[0] == '!' || line[0] == '[' {
			continue
		}
		if i := strings.IndexByte(line, '#'); i >= 0 {
			line = strings.TrimSpace(line[:i])
		}
		f := strings.Fields(line)
		if len(f) == 0 {
			continue
		}
		var names []string
		if net.ParseIP(f[0]) != nil {
			names = f[1:]
		} else if strings.HasPrefix(f[0], "||") {
			r := strings.TrimPrefix(f[0], "||")
			// only pure domain rules: ||example.com^ - skip path/option rules
			if i := strings.IndexByte(r, '^'); i >= 0 {
				if rest := r[i+1:]; rest != "" && rest != "$important" {
					continue
				}
				r = r[:i]
			}
			if strings.ContainsAny(r, "/*?=") {
				continue
			}
			names = []string{r}
		} else {
			names = f[:1]
		}
		for _, d := range names {
			d = clean(d)
			if d == "" || d == "localhost" || d == "localhost.localdomain" || d == "local" ||
				d == "broadcasthost" || d == "ip6-localhost" || d == "ip6-loopback" || d == "0.0.0.0" {
				continue
			}
			if _, dup := dst[d]; !dup {
				dst[d] = struct{}{}
				n++
			}
		}
	}
	return n, sc.Err()
}

func clean(d string) string {
	d = normalise(d)
	d = strings.TrimPrefix(d, "*.")
	// single labels ("ads", "localhost") are junk in public lists, and
	// anything with spaces/slashes isn't a hostname
	if d == "" || strings.ContainsAny(d, " /:@\\") || !strings.Contains(d, ".") {
		return ""
	}
	return d
}

func normalise(d string) string {
	return strings.TrimSuffix(strings.ToLower(strings.TrimSpace(d)), ".")
}
