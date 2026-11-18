package block

import (
	"strings"
	"testing"
)

func TestParseFormats(t *testing.T) {
	in := `# a hosts file
0.0.0.0 ads.example.com tracker.example.com
127.0.0.1 localhost
::1 ip6-localhost
plain-domain.net
||adblock-style.org^
||with-path.org/banner.js
||with-option.org^$third-party
*.wild.io
singlelabel
! adblock comment
[Adblock Plus 2.0]
`
	m := map[string]struct{}{}
	n, err := Parse(strings.NewReader(in), m)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"ads.example.com", "tracker.example.com", "plain-domain.net", "adblock-style.org", "wild.io"}
	if n != len(want) {
		t.Fatalf("got %d entries: %v", n, m)
	}
	for _, w := range want {
		if _, ok := m[w]; !ok {
			t.Errorf("missing %s", w)
		}
	}
}

func TestMatchSubdomainsAndAllow(t *testing.T) {
	l := New()
	l.Replace(map[string]struct{}{"doubleclick.net": {}, "example.com": {}})
	l.Allow("cdn.example.com")
	cases := map[string]bool{
		"doubleclick.net":      true,
		"ad.g.doubleclick.net": true,
		"DoubleClick.NET.":     true,
		"notdoubleclick.net":   false,
		"example.com":          true,
		"cdn.example.com":      false,
		"img.cdn.example.com":  false,
		"github.com":           false,
	}
	for name, want := range cases {
		if got, _ := l.Match(name); got != want {
			t.Errorf("%s: got %v want %v", name, got, want)
		}
	}
	if _, rule := l.Match("ad.g.doubleclick.net"); rule != "doubleclick.net" {
		t.Errorf("rule = %q", rule)
	}
}
