package vault

import (
	"sync"
	"time"
)

// ttlItem holds a cached value and its absolute expiration (Unix seconds).
// Internal helper; not exported.
type ttlItem[T any] struct {
	v   T
	exp int64
}

// TTLCache is a tiny, goroutine-safe in-memory key/value cache with a fixed
// capacity and a time-to-live (TTL) applied to each entry.
//
//   - Concurrency: protected by a single mutex; safe for concurrent use.
//   - Expiration: entries expire lazily on Get when their exp < now.
//   - Eviction: when capacity is reached, the oldest *inserted key* is evicted
//     (simple FIFO). Each Set appends the key to a FIFO queue; duplicate keys
//     therefore occupy multiple positions and may be evicted earlier than an
//     LRU would.
//   - Time resolution: expiration is tracked at 1-second granularity.
//   - Zero value: the zero value of TTLCache is not ready for use; call
//     NewTTLCache to initialize internal fields.
type TTLCache[T any] struct {
	mu   sync.Mutex
	ttl  time.Duration
	size int
	data map[string]ttlItem[T]
	keys []string // simple FIFO eviction queue (by insertion occurrences)
}

// NewTTLCache constructs a TTLCache with the given maximum size and TTL per
// entry. A non-positive ttl effectively disables caching (items expire
// immediately).
func NewTTLCache[T any](size int, ttl time.Duration) *TTLCache[T] {
	return &TTLCache[T]{ttl: ttl, size: size, data: make(map[string]ttlItem[T])}
}

// Get returns the cached value for key k if present and not expired.
// On hit, it returns (value, true). If the key is absent or the entry has
// expired, it returns the zero value of T and false. Expired entries are
// removed lazily during this call.
func (c *TTLCache[T]) Get(k string) (T, bool) {
	var zero T
	now := time.Now().Unix()
	c.mu.Lock()
	defer c.mu.Unlock()
	it, ok := c.data[k]
	if !ok || it.exp < now {
		if ok {
			delete(c.data, k)
		}
		return zero, false
	}
	return it.v, true
}

// Set inserts or replaces the value for key k with an expiration time of
// now + cache TTL. If the cache is at capacity, it evicts the oldest key
// according to the internal FIFO queue and then inserts the new item.
//
// Note: each call appends k to the FIFO queue. If the same key is Set
// repeatedly, older queue entries remain; when they reach the front, the
// eviction step will delete the current mapping for k. This behavior is
// intentional for simplicity (FIFO by insertion), and differs from LRU.
func (c *TTLCache[T]) Set(k string, v T) {
	now := time.Now().Add(c.ttl).Unix()
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.data) >= c.size {
		// evict oldest key by insertion order
		if len(c.keys) > 0 {
			old := c.keys[0]
			c.keys = c.keys[1:]
			delete(c.data, old)
		}
	}
	c.data[k] = ttlItem[T]{v: v, exp: now}
	c.keys = append(c.keys, k)
}
