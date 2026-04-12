package vibecoder

// Feature: cybermind-vibe-coder, Property 15: Response Cache Round-Trip and Latency
// Validates: Requirements (cache round-trip, LRU eviction, disk persistence)

import (
	"fmt"
	"os"
	"testing"
	"time"
)

// TestResponseCacheRoundTrip verifies that after Set, Get returns the same response.
func TestResponseCacheRoundTrip(t *testing.T) {
	c := NewResponseCache("")

	entry := CacheEntry{
		PromptHash: "abc123",
		Response:   "hello world",
		CreatedAt:  time.Now(),
	}
	c.Set("abc123", entry)

	got, ok := c.Get("abc123")
	if !ok {
		t.Fatal("expected cache hit, got miss")
	}
	if got.Response != entry.Response {
		t.Fatalf("expected %q, got %q", entry.Response, got.Response)
	}
}

// TestResponseCacheIdempotentGet verifies that a second Get returns the same response.
func TestResponseCacheIdempotentGet(t *testing.T) {
	c := NewResponseCache("")

	entry := CacheEntry{PromptHash: "key1", Response: "resp1", CreatedAt: time.Now()}
	c.Set("key1", entry)

	got1, ok1 := c.Get("key1")
	got2, ok2 := c.Get("key1")

	if !ok1 || !ok2 {
		t.Fatal("expected both Gets to hit")
	}
	if got1.Response != got2.Response {
		t.Fatalf("idempotency violated: %q != %q", got1.Response, got2.Response)
	}
}

// TestResponseCacheMemoryOnly verifies memory cache serves hits without disk I/O (diskDir="").
func TestResponseCacheMemoryOnly(t *testing.T) {
	c := NewResponseCache("") // no disk

	entry := CacheEntry{PromptHash: "mem1", Response: "memory-only", CreatedAt: time.Now()}
	c.Set("mem1", entry)

	got, ok := c.Get("mem1")
	if !ok {
		t.Fatal("expected memory hit")
	}
	if got.Response != "memory-only" {
		t.Fatalf("unexpected response: %q", got.Response)
	}
}

// TestResponseCacheLRUEviction verifies that after 51 entries, the first entry is evicted.
func TestResponseCacheLRUEviction(t *testing.T) {
	c := NewResponseCache("")

	// Insert maxMemEntries+1 entries; first key should be evicted
	firstKey := "entry-0"
	for i := 0; i <= maxMemEntries; i++ {
		key := fmt.Sprintf("entry-%d", i)
		c.Set(key, CacheEntry{PromptHash: key, Response: key, CreatedAt: time.Now()})
	}

	_, ok := c.Get(firstKey)
	if ok {
		t.Fatalf("expected %q to be evicted after %d insertions", firstKey, maxMemEntries+1)
	}

	// The last inserted entry must still be present
	lastKey := fmt.Sprintf("entry-%d", maxMemEntries)
	got, ok := c.Get(lastKey)
	if !ok {
		t.Fatalf("expected %q to be in cache", lastKey)
	}
	if got.Response != lastKey {
		t.Fatalf("unexpected response for last key: %q", got.Response)
	}
}

// TestResponseCacheDiskPersistence verifies that a new cache instance finds entries written by a previous one.
func TestResponseCacheDiskPersistence(t *testing.T) {
	dir, err := os.MkdirTemp("", "vibecache-test-*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(dir)

	entry := CacheEntry{PromptHash: "persist1", Response: "persisted-response", CreatedAt: time.Now()}

	// Write with first instance
	c1 := NewResponseCache(dir)
	c1.Set("persist1", entry)

	// Read with a fresh instance (cold memory)
	c2 := NewResponseCache(dir)
	got, ok := c2.Get("persist1")
	if !ok {
		t.Fatal("expected disk hit on new cache instance")
	}
	if got.Response != entry.Response {
		t.Fatalf("expected %q, got %q", entry.Response, got.Response)
	}
}
