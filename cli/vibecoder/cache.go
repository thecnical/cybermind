package vibecoder

import (
	"container/list"
	"encoding/json"
	"os"
	"path/filepath"
	"sync"
	"time"
)

const maxMemEntries = 50

// CacheEntry holds a cached prompt/response pair.
type CacheEntry struct {
	PromptHash string    `json:"prompt_hash"`
	Response   string    `json:"response"`
	CreatedAt  time.Time `json:"created_at"`
}

// lruEntry is the value stored inside the doubly-linked list.
type lruEntry struct {
	key   string
	value CacheEntry
}

// ResponseCache is a two-level cache: in-memory LRU + optional disk store.
type ResponseCache struct {
	mu      sync.RWMutex
	mem     map[string]*list.Element // key -> list element
	order   *list.List               // front = most recently used
	diskDir string
}

// NewResponseCache creates a ResponseCache with disk storage at diskDir.
// If diskDir is empty, disk caching is disabled.
func NewResponseCache(diskDir string) *ResponseCache {
	return &ResponseCache{
		mem:     make(map[string]*list.Element),
		order:   list.New(),
		diskDir: diskDir,
	}
}

// Get looks up a cache entry by prompt hash.
// Checks memory first, then disk. Returns the entry and true if found.
func (c *ResponseCache) Get(promptHash string) (CacheEntry, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()

	// Fast path: memory
	if elem, ok := c.mem[promptHash]; ok {
		c.order.MoveToFront(elem)
		return elem.Value.(*lruEntry).value, true
	}

	// Slow path: disk
	if c.diskDir == "" {
		return CacheEntry{}, false
	}

	data, err := os.ReadFile(c.diskPath(promptHash))
	if err != nil {
		return CacheEntry{}, false
	}

	var entry CacheEntry
	if err := json.Unmarshal(data, &entry); err != nil {
		return CacheEntry{}, false
	}

	// Promote into memory
	c.addToMem(promptHash, entry)
	return entry, true
}

// Set stores a cache entry in both memory and disk.
func (c *ResponseCache) Set(promptHash string, entry CacheEntry) {
	c.mu.Lock()
	defer c.mu.Unlock()

	// Update existing element in memory if present
	if elem, ok := c.mem[promptHash]; ok {
		elem.Value.(*lruEntry).value = entry
		c.order.MoveToFront(elem)
	} else {
		c.addToMem(promptHash, entry)
	}

	// Persist to disk
	if c.diskDir == "" {
		return
	}

	if err := os.MkdirAll(c.diskDir, 0700); err != nil {
		return
	}

	data, err := json.Marshal(entry)
	if err != nil {
		return
	}

	_ = atomicWrite(c.diskPath(promptHash), data)
}

// diskPath returns the path for a cache entry on disk.
func (c *ResponseCache) diskPath(promptHash string) string {
	return filepath.Join(c.diskDir, promptHash+".json")
}

// addToMem inserts a new entry at the front of the LRU list.
// Must be called with c.mu held.
func (c *ResponseCache) addToMem(key string, entry CacheEntry) {
	// Evict LRU if at capacity
	if c.order.Len() >= maxMemEntries {
		back := c.order.Back()
		if back != nil {
			c.order.Remove(back)
			delete(c.mem, back.Value.(*lruEntry).key)
		}
	}

	elem := c.order.PushFront(&lruEntry{key: key, value: entry})
	c.mem[key] = elem
}
