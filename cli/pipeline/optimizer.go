package pipeline

import (
	"crypto/sha1"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

type ConcurrencyProfile struct {
	Name            string
	PhaseWorkers    map[int]int
	CrawlDepth      int
	CrawlConcurrency int
}

func AdaptiveProfile(mode, target string, wafDetected bool) ConcurrencyProfile {
	isIP := true
	for _, c := range target {
		if (c < '0' || c > '9') && c != '.' && c != ':' && c != '/' {
			isIP = false
			break
		}
	}
	base := ConcurrencyProfile{
		Name: "balanced",
		PhaseWorkers: map[int]int{
			1: 4, 2: 4, 3: 2, 4: 4, 5: 2, 6: 2,
		},
		CrawlDepth:      3,
		CrawlConcurrency: 25,
	}
	if mode == "hunt" {
		base.PhaseWorkers[1] = 3
		base.PhaseWorkers[2] = 3
		base.PhaseWorkers[4] = 3
	}
	if isIP {
		base.Name = "network-focused"
		base.PhaseWorkers[1] = 2
		base.PhaseWorkers[2] = 2
		base.PhaseWorkers[3] = 3
		base.PhaseWorkers[4] = 2
	}
	if wafDetected {
		base.Name = "stealth-waf"
		for k, v := range base.PhaseWorkers {
			if v > 1 {
				base.PhaseWorkers[k] = v - 1
			}
		}
		base.CrawlConcurrency = 10
	}
	return base
}

type CrawlTask struct {
	URL   string
	Depth int
	Mode  string
}

type CrawlScheduler struct {
	mu      sync.Mutex
	seen    map[string]bool
	queue   []CrawlTask
	maxSize int
}

func NewCrawlScheduler(maxSize int) *CrawlScheduler {
	if maxSize <= 0 {
		maxSize = 1000
	}
	return &CrawlScheduler{seen: map[string]bool{}, maxSize: maxSize}
}

func (s *CrawlScheduler) Enqueue(url string, depth int, mode string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	url = strings.TrimSpace(url)
	if url == "" || s.seen[url] || len(s.queue) >= s.maxSize {
		return false
	}
	s.seen[url] = true
	s.queue = append(s.queue, CrawlTask{URL: url, Depth: depth, Mode: mode})
	return true
}

func (s *CrawlScheduler) Drain(limit int) []CrawlTask {
	s.mu.Lock()
	defer s.mu.Unlock()
	if limit <= 0 || limit > len(s.queue) {
		limit = len(s.queue)
	}
	out := append([]CrawlTask(nil), s.queue[:limit]...)
	s.queue = s.queue[limit:]
	sort.Slice(out, func(i, j int) bool { return out[i].Depth < out[j].Depth })
	return out
}

type passiveCacheRecord struct {
	Target    string    `json:"target"`
	Tool      string    `json:"tool"`
	Output    string    `json:"output"`
	UpdatedAt time.Time `json:"updated_at"`
}

type PassiveCache struct {
	mu      sync.Mutex
	ttl     time.Duration
	baseDir string
}

func NewPassiveCache(ttl time.Duration) *PassiveCache {
	if ttl <= 0 {
		ttl = 6 * time.Hour
	}
	base := filepath.Join(os.TempDir(), "cybermind_passive_cache")
	_ = os.MkdirAll(base, 0700)
	return &PassiveCache{ttl: ttl, baseDir: base}
}

func (c *PassiveCache) key(target, tool string) string {
	sum := sha1.Sum([]byte(target + "|" + tool))
	return hex.EncodeToString(sum[:]) + ".json"
}

func (c *PassiveCache) Get(target, tool string) (string, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	p := filepath.Join(c.baseDir, c.key(target, tool))
	b, err := os.ReadFile(p)
	if err != nil {
		return "", false
	}
	var rec passiveCacheRecord
	if json.Unmarshal(b, &rec) != nil {
		return "", false
	}
	if time.Since(rec.UpdatedAt) > c.ttl {
		return "", false
	}
	return rec.Output, true
}

func (c *PassiveCache) Set(target, tool, output string) {
	if strings.TrimSpace(output) == "" {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	rec := passiveCacheRecord{Target: target, Tool: tool, Output: output, UpdatedAt: time.Now()}
	b, _ := json.Marshal(rec)
	_ = os.WriteFile(filepath.Join(c.baseDir, c.key(target, tool)), b, 0600)
}

type QueueTask struct {
	ID      string    `json:"id"`
	Mode    string    `json:"mode"`
	Target  string    `json:"target"`
	Payload string    `json:"payload"`
	Created time.Time `json:"created"`
}

type DistributedQueue struct {
	mu    sync.Mutex
	tasks []QueueTask
	file  string
}

func NewDistributedQueue() *DistributedQueue {
	q := &DistributedQueue{file: filepath.Join(os.TempDir(), "cybermind_distributed_queue.json")}
	q.load()
	return q
}

func (q *DistributedQueue) load() {
	b, err := os.ReadFile(q.file)
	if err != nil {
		return
	}
	_ = json.Unmarshal(b, &q.tasks)
}

func (q *DistributedQueue) persist() {
	b, _ := json.Marshal(q.tasks)
	_ = os.WriteFile(q.file, b, 0600)
}

func (q *DistributedQueue) Enqueue(mode, target, payload string) {
	q.mu.Lock()
	defer q.mu.Unlock()
	sum := sha1.Sum([]byte(time.Now().String() + mode + target + payload))
	id := hex.EncodeToString(sum[:])
	q.tasks = append(q.tasks, QueueTask{ID: id, Mode: mode, Target: target, Payload: payload, Created: time.Now()})
	q.persist()
}

func (q *DistributedQueue) Dequeue(mode string) (QueueTask, bool) {
	q.mu.Lock()
	defer q.mu.Unlock()
	for i, t := range q.tasks {
		if mode == "" || t.Mode == mode {
			out := t
			q.tasks = append(q.tasks[:i], q.tasks[i+1:]...)
			q.persist()
			return out, true
		}
	}
	return QueueTask{}, false
}

func ConfidenceScore(vulns, xss, creds int, waf bool) int {
	score := vulnScore(vulns) + minInt(xss*8, 24) + minInt(creds*15, 30)
	if waf {
		score -= 8
	}
	if score < 0 {
		return 0
	}
	if score > 100 {
		return 100
	}
	return score
}

func vulnScore(v int) int {
	switch {
	case v >= 8:
		return 50
	case v >= 4:
		return 35
	case v >= 1:
		return 18
	default:
		return 0
	}
}

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}

