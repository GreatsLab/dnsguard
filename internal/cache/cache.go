// Package cache is a TTL-aware LRU for DNS answers.
package cache

import (
	"container/list"
	"sync"
	"time"
)

type entry struct {
	key     string
	msg     []byte
	stored  time.Time
	expires time.Time
}

type Cache struct {
	mu    sync.Mutex
	max   int
	ll    *list.List
	items map[string]*list.Element
	now   func() time.Time

	hits, misses uint64
}

// Counters returns cache hits and misses since start.
func (c *Cache) Counters() (hits, misses uint64) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.hits, c.misses
}

func New(max int) *Cache {
	return &Cache{max: max, ll: list.New(), items: map[string]*list.Element{}, now: time.Now}
}

// Get returns a copy of the cached answer and how many seconds of its TTL
// are left, or ok=false.
func (c *Cache) Get(key string) (msg []byte, remaining uint32, ok bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	el, ok := c.items[key]
	if !ok {
		c.misses++
		return nil, 0, false
	}
	e := el.Value.(*entry)
	now := c.now()
	if !now.Before(e.expires) {
		c.ll.Remove(el)
		delete(c.items, key)
		c.misses++
		return nil, 0, false
	}
	c.ll.MoveToFront(el)
	c.hits++
	out := make([]byte, len(e.msg))
	copy(out, e.msg)
	left := e.expires.Sub(now).Seconds()
	if left < 1 {
		left = 1
	}
	return out, uint32(left), true
}

func (c *Cache) Set(key string, msg []byte, ttl time.Duration) {
	if ttl <= 0 || c.max <= 0 {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	now := c.now()
	cp := make([]byte, len(msg))
	copy(cp, msg)
	if el, ok := c.items[key]; ok {
		e := el.Value.(*entry)
		e.msg, e.stored, e.expires = cp, now, now.Add(ttl)
		c.ll.MoveToFront(el)
		return
	}
	c.items[key] = c.ll.PushFront(&entry{key: key, msg: cp, stored: now, expires: now.Add(ttl)})
	for c.ll.Len() > c.max {
		old := c.ll.Back()
		c.ll.Remove(old)
		delete(c.items, old.Value.(*entry).key)
	}
}

// SetClock swaps the time source (tests).
func (c *Cache) SetClock(now func() time.Time) {
	c.mu.Lock()
	c.now = now
	c.mu.Unlock()
}

func (c *Cache) Len() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.ll.Len()
}

func (c *Cache) Flush() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.ll.Init()
	c.items = map[string]*list.Element{}
}
