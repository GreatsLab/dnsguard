package cache

import (
	"testing"
	"time"
)

func TestTTLAndLRU(t *testing.T) {
	now := time.Unix(1000, 0)
	c := New(2)
	c.now = func() time.Time { return now }
	c.Set("a", []byte("A"), 30*time.Second)
	c.Set("b", []byte("B"), 30*time.Second)
	now = now.Add(10 * time.Second)
	msg, left, ok := c.Get("a")
	if !ok || string(msg) != "A" || left != 20 {
		t.Fatalf("got %q %d %v", msg, left, ok)
	}
	msg[0] = 'X' // callers get a copy
	if m, _, _ := c.Get("a"); string(m) != "A" {
		t.Fatal("cache returned shared memory")
	}
	c.Set("c", []byte("C"), time.Minute) // evicts b (least recently used)
	if _, _, ok := c.Get("b"); ok {
		t.Fatal("b should be evicted")
	}
	now = now.Add(25 * time.Second)
	if _, _, ok := c.Get("a"); ok {
		t.Fatal("a should have expired")
	}
	if h, m := c.Counters(); h != 2 || m != 2 {
		t.Fatalf("hits/misses %d/%d", h, m)
	}
}
