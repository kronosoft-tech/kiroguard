package llm

import (
	"container/list"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"sync"
	"sync/atomic"
)

const defaultCacheCapacity = 1000

type cacheEntry struct {
	key      string
	response *LLMResponse
}

// CacheStats provides operational metrics for the LRU prompt cache.
type CacheStats struct {
	Hits      int64 `json:"hits"`
	Misses    int64 `json:"misses"`
	Evictions int64 `json:"evictions"`
	Size      int   `json:"size"`
	Capacity  int   `json:"capacity"`
}

// CachedLLM wraps an LLMBackend with an O(1) LRU (Least Recently Used) cache.
// It computes a SHA-256 hash of Prompt.System + Prompt.User as the cache key.
// Identical prompts return cached LLM responses in 0ms without consuming tokens
// or invoking external APIs.
type CachedLLM struct {
	backend   LLMBackend
	capacity  int
	mu        sync.Mutex
	items     map[string]*list.Element
	evictList *list.List

	hits      atomic.Int64
	misses    atomic.Int64
	evictions atomic.Int64
}

// NewCachedLLM creates a thread-safe LRU cache wrapper around an LLMBackend.
func NewCachedLLM(backend LLMBackend, capacity int) *CachedLLM {
	if capacity <= 0 {
		capacity = defaultCacheCapacity
	}
	return &CachedLLM{
		backend:   backend,
		capacity:  capacity,
		items:     make(map[string]*list.Element),
		evictList: list.New(),
	}
}

// Complete satisfies the LLMBackend interface.
// If the prompt prompt exists in the LRU cache, it returns a copy of the cached response
// with metadata["cached"] = "true". Otherwise, it delegates to the inner LLMBackend
// and stores successful responses in the LRU cache.
func (c *CachedLLM) Complete(ctx context.Context, p Prompt) (*LLMResponse, error) {
	key := hashPrompt(p)

	// Check LRU cache under lock
	c.mu.Lock()
	if elem, found := c.items[key]; found {
		c.evictList.MoveToFront(elem)
		entry := elem.Value.(*cacheEntry)
		c.mu.Unlock()
		c.hits.Add(1)

		// Clone response to avoid caller mutation
		cloned := cloneResponse(entry.response)
		if cloned.Metadata == nil {
			cloned.Metadata = make(map[string]string)
		}
		cloned.Metadata["cached"] = "true"
		return cloned, nil
	}
	c.mu.Unlock()

	c.misses.Add(1)

	// Cache miss: invoke underlying backend
	resp, err := c.backend.Complete(ctx, p)
	if err != nil {
		return nil, err
	}

	// Store in LRU cache under lock
	c.mu.Lock()
	defer c.mu.Unlock()

	// Re-check after unlocking to handle concurrent callers
	if elem, found := c.items[key]; found {
		c.evictList.MoveToFront(elem)
		elem.Value.(*cacheEntry).response = cloneResponse(resp)
		return resp, nil
	}

	entry := &cacheEntry{
		key:      key,
		response: cloneResponse(resp),
	}
	elem := c.evictList.PushFront(entry)
	c.items[key] = elem

	// Evict oldest item if over capacity
	if c.evictList.Len() > c.capacity {
		c.removeOldest()
	}

	return resp, nil
}

// removeOldest evicts the least recently used element from the cache. Must be called under c.mu lock.
func (c *CachedLLM) removeOldest() {
	elem := c.evictList.Back()
	if elem != nil {
		c.evictList.Remove(elem)
		kv := elem.Value.(*cacheEntry)
		delete(c.items, kv.key)
		c.evictions.Add(1)
	}
}

// Stats returns a point-in-time snapshot of cache performance metrics.
func (c *CachedLLM) Stats() CacheStats {
	c.mu.Lock()
	size := len(c.items)
	c.mu.Unlock()

	return CacheStats{
		Hits:      c.hits.Load(),
		Misses:    c.misses.Load(),
		Evictions: c.evictions.Load(),
		Size:      size,
		Capacity:  c.capacity,
	}
}

// Clear flushes all entries from the LRU cache.
func (c *CachedLLM) Clear() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.items = make(map[string]*list.Element)
	c.evictList.Init()
}

// hashPrompt computes a deterministic SHA-256 hash of Prompt.System + Prompt.User.
func hashPrompt(p Prompt) string {
	h := sha256.New()
	h.Write([]byte("sys:"))
	h.Write([]byte(p.System))
	h.Write([]byte("\nuser:"))
	h.Write([]byte(p.User))
	return hex.EncodeToString(h.Sum(nil))
}

// cloneResponse creates a deep copy of an LLMResponse.
func cloneResponse(resp *LLMResponse) *LLMResponse {
	if resp == nil {
		return nil
	}
	meta := make(map[string]string, len(resp.Metadata))
	for k, v := range resp.Metadata {
		meta[k] = v
	}
	return &LLMResponse{
		Text:     resp.Text,
		Metadata: meta,
	}
}
