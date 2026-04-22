// Package breach — CyberMind Breach Intelligence Module
// 90% API-based (HIBP, LeakCheck, IntelX, DeHashed, BreachDirectory)
// 10% local dump fallback (SQLite-indexed user-provided dumps)
//
// Integrated into /osint-deep Phase 2 automatically.
// Also callable standalone via runBreachCheck() in commands.go
package breach

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	_ "github.com/mattn/go-sqlite3"
)

// ─── Types ────────────────────────────────────────────────────────────────────

// BreachResult holds findings from all breach sources.
type BreachResult struct {
	Target   string
	Type     string // "email" | "domain" | "username"
	Breaches []BreachEntry
	Sources  []string // which APIs returned data
	Error    string
}

// BreachEntry is a single breach record.
type BreachEntry struct {
	Source    string    // "hibp" | "leakcheck" | "dehashed" | "local"
	Name      string    // breach name (e.g. "LinkedIn")
	Date      string    // breach date
	Count     int64     // number of records
	DataTypes []string  // what was leaked (email, password, phone, etc.)
	Password  string    // leaked password (if available from local dump)
	Hash      string    // leaked hash (if available)
	Found     time.Time
}

// ─── API Clients ──────────────────────────────────────────────────────────────

var httpClient = &http.Client{Timeout: 10 * time.Second}

// CheckHIBP queries Have I Been Pwned API (free, no key for basic check).
// Returns breach list for an email address.
func CheckHIBP(email string) ([]BreachEntry, error) {
	if !strings.Contains(email, "@") {
		return nil, fmt.Errorf("HIBP requires email address")
	}

	// HIBP v3 API — truncated response (no passwords, just breach names)
	reqURL := fmt.Sprintf("https://haveibeenpwned.com/api/v3/breachedaccount/%s?truncateResponse=false",
		url.PathEscape(email))

	req, err := http.NewRequest("GET", reqURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "CyberMind-OSINT/1.0")
	req.Header.Set("hibp-api-key", getHIBPKey()) // optional — works without key for basic

	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode == 404 {
		return nil, nil // not found = no breaches
	}
	if resp.StatusCode == 401 {
		// No API key — use free endpoint
		return checkHIBPFree(email)
	}
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("HIBP API returned %d", resp.StatusCode)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
	if err != nil {
		return nil, err
	}

	var raw []map[string]interface{}
	if err := json.Unmarshal(body, &raw); err != nil {
		return nil, err
	}

	var entries []BreachEntry
	for _, b := range raw {
		entry := BreachEntry{Source: "hibp", Found: time.Now()}
		if name, ok := b["Name"].(string); ok {
			entry.Name = name
		}
		if date, ok := b["BreachDate"].(string); ok {
			entry.Date = date
		}
		if count, ok := b["PwnCount"].(float64); ok {
			entry.Count = int64(count)
		}
		if types, ok := b["DataClasses"].([]interface{}); ok {
			for _, t := range types {
				if s, ok := t.(string); ok {
					entry.DataTypes = append(entry.DataTypes, s)
				}
			}
		}
		entries = append(entries, entry)
	}
	return entries, nil
}

// checkHIBPFree uses the free HIBP search (no API key, limited).
func checkHIBPFree(email string) ([]BreachEntry, error) {
	reqURL := fmt.Sprintf("https://haveibeenpwned.com/api/v3/breachedaccount/%s",
		url.PathEscape(email))
	req, _ := http.NewRequest("GET", reqURL, nil)
	req.Header.Set("User-Agent", "CyberMind-OSINT/1.0")

	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode == 404 {
		return nil, nil
	}
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("HIBP free API: %d", resp.StatusCode)
	}

	body, _ := io.ReadAll(io.LimitReader(resp.Body, 32*1024))
	var raw []map[string]interface{}
	if err := json.Unmarshal(body, &raw); err != nil {
		return nil, err
	}

	var entries []BreachEntry
	for _, b := range raw {
		entry := BreachEntry{Source: "hibp-free", Found: time.Now()}
		if name, ok := b["Name"].(string); ok {
			entry.Name = name
		}
		entries = append(entries, entry)
	}
	return entries, nil
}

// CheckLeakCheck queries LeakCheck.io free API (5B+ records).
func CheckLeakCheck(target string) ([]BreachEntry, error) {
	reqURL := fmt.Sprintf("https://leakcheck.io/api/public?check=%s", url.QueryEscape(target))

	req, _ := http.NewRequest("GET", reqURL, nil)
	req.Header.Set("User-Agent", "CyberMind-OSINT/1.0")

	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("LeakCheck API: %d", resp.StatusCode)
	}

	body, _ := io.ReadAll(io.LimitReader(resp.Body, 32*1024))

	var result struct {
		Success bool                     `json:"success"`
		Found   int                      `json:"found"`
		Sources []map[string]interface{} `json:"sources"`
	}
	if err := json.Unmarshal(body, &result); err != nil {
		return nil, err
	}

	if !result.Success || result.Found == 0 {
		return nil, nil
	}

	var entries []BreachEntry
	for _, s := range result.Sources {
		entry := BreachEntry{Source: "leakcheck", Found: time.Now()}
		if name, ok := s["name"].(string); ok {
			entry.Name = name
		}
		if date, ok := s["date"].(string); ok {
			entry.Date = date
		}
		entries = append(entries, entry)
	}
	return entries, nil
}

// CheckBreachDirectory queries BreachDirectory.org free API.
func CheckBreachDirectory(email string) ([]BreachEntry, error) {
	if !strings.Contains(email, "@") {
		return nil, nil
	}

	reqURL := fmt.Sprintf("https://breachdirectory.org/api?func=auto&term=%s", url.QueryEscape(email))
	req, _ := http.NewRequest("GET", reqURL, nil)
	req.Header.Set("User-Agent", "CyberMind-OSINT/1.0")
	req.Header.Set("X-Api-Key", getBreachDirKey())

	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("BreachDirectory API: %d", resp.StatusCode)
	}

	body, _ := io.ReadAll(io.LimitReader(resp.Body, 32*1024))

	var result struct {
		Success bool                     `json:"success"`
		Found   int                      `json:"found"`
		Result  []map[string]interface{} `json:"result"`
	}
	if err := json.Unmarshal(body, &result); err != nil {
		return nil, err
	}

	var entries []BreachEntry
	for _, r := range result.Result {
		entry := BreachEntry{Source: "breachdirectory", Found: time.Now()}
		if src, ok := r["sources"].([]interface{}); ok && len(src) > 0 {
			if s, ok := src[0].(string); ok {
				entry.Name = s
			}
		}
		if hash, ok := r["sha1"].(string); ok {
			entry.Hash = hash
		}
		if pass, ok := r["password"].(string); ok {
			entry.Password = pass
		}
		entries = append(entries, entry)
	}
	return entries, nil
}

// CheckIntelX queries IntelX.io free tier.
func CheckIntelX(target string) ([]BreachEntry, error) {
	// IntelX search API
	searchURL := "https://2.intelx.io/intelligent/search"
	payload := fmt.Sprintf(`{"term":"%s","buckets":[],"lookuplevel":0,"maxresults":10,"timeout":0,"datefrom":"","dateto":"","sort":4,"media":0,"terminate":[]}`, target)

	req, _ := http.NewRequest("POST", searchURL, strings.NewReader(payload))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "CyberMind-OSINT/1.0")
	req.Header.Set("x-key", getIntelXKey())

	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("IntelX API: %d", resp.StatusCode)
	}

	body, _ := io.ReadAll(io.LimitReader(resp.Body, 32*1024))

	var result struct {
		ID     string `json:"id"`
		Status int    `json:"status"`
	}
	if err := json.Unmarshal(body, &result); err != nil {
		return nil, err
	}

	if result.ID == "" {
		return nil, nil
	}

	// Get results
	resultsURL := fmt.Sprintf("https://2.intelx.io/intelligent/search/result?id=%s&limit=10&offset=0", result.ID)
	req2, _ := http.NewRequest("GET", resultsURL, nil)
	req2.Header.Set("x-key", getIntelXKey())

	resp2, err := httpClient.Do(req2)
	if err != nil {
		return nil, err
	}
	defer resp2.Body.Close()

	body2, _ := io.ReadAll(io.LimitReader(resp2.Body, 32*1024))

	var results struct {
		Records []map[string]interface{} `json:"records"`
	}
	if err := json.Unmarshal(body2, &results); err != nil {
		return nil, err
	}

	var entries []BreachEntry
	for _, r := range results.Records {
		entry := BreachEntry{Source: "intelx", Found: time.Now()}
		if name, ok := r["name"].(string); ok {
			entry.Name = name
		}
		if date, ok := r["date"].(string); ok {
			entry.Date = date
		}
		entries = append(entries, entry)
	}
	return entries, nil
}

// ─── Local Dump Index ─────────────────────────────────────────────────────────

// IndexLocalDump indexes a breach dump file into SQLite for fast searching.
// Supports: email:password, email:hash, plain email lists.
func IndexLocalDump(dumpPath string) error {
	dbPath := getLocalDBPath()
	db, err := sql.Open("sqlite3", dbPath)
	if err != nil {
		return fmt.Errorf("open db: %v", err)
	}
	defer db.Close()

	// Create table
	_, err = db.Exec(`CREATE TABLE IF NOT EXISTS breaches (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		email TEXT NOT NULL,
		password TEXT,
		hash TEXT,
		source TEXT,
		indexed_at DATETIME DEFAULT CURRENT_TIMESTAMP
	)`)
	if err != nil {
		return fmt.Errorf("create table: %v", err)
	}
	_, _ = db.Exec(`CREATE INDEX IF NOT EXISTS idx_email ON breaches(email)`)

	// Read and index dump file
	data, err := os.ReadFile(dumpPath)
	if err != nil {
		return fmt.Errorf("read dump: %v", err)
	}

	source := filepath.Base(dumpPath)
	lines := strings.Split(string(data), "\n")

	tx, _ := db.Begin()
	stmt, _ := tx.Prepare(`INSERT OR IGNORE INTO breaches (email, password, hash, source) VALUES (?, ?, ?, ?)`)
	defer stmt.Close()

	count := 0
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		var email, password, hash string

		if strings.Contains(line, ":") {
			parts := strings.SplitN(line, ":", 2)
			email = strings.ToLower(strings.TrimSpace(parts[0]))
			val := strings.TrimSpace(parts[1])
			// Detect if it's a hash (32+ hex chars) or password
			if len(val) >= 32 && isHex(val) {
				hash = val
			} else {
				password = val
			}
		} else if strings.Contains(line, "@") {
			email = strings.ToLower(strings.TrimSpace(line))
		} else {
			continue
		}

		if !strings.Contains(email, "@") {
			continue
		}

		stmt.Exec(email, password, hash, source)
		count++

		if count%10000 == 0 {
			tx.Commit()
			tx, _ = db.Begin()
			stmt, _ = tx.Prepare(`INSERT OR IGNORE INTO breaches (email, password, hash, source) VALUES (?, ?, ?, ?)`)
		}
	}
	tx.Commit()

	fmt.Printf("Indexed %d records from %s\n", count, source)
	return nil
}

// SearchLocalDump searches the local SQLite breach database.
func SearchLocalDump(target string) ([]BreachEntry, error) {
	dbPath := getLocalDBPath()
	if _, err := os.Stat(dbPath); err != nil {
		return nil, nil // no local db
	}

	db, err := sql.Open("sqlite3", dbPath)
	if err != nil {
		return nil, err
	}
	defer db.Close()

	var query string
	var args []interface{}

	if strings.Contains(target, "@") {
		// Email search
		query = `SELECT email, password, hash, source FROM breaches WHERE email = ? LIMIT 50`
		args = []interface{}{strings.ToLower(target)}
	} else if strings.Contains(target, ".") {
		// Domain search
		query = `SELECT email, password, hash, source FROM breaches WHERE email LIKE ? LIMIT 100`
		args = []interface{}{"%" + target}
	} else {
		return nil, nil
	}

	rows, err := db.Query(query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var entries []BreachEntry
	for rows.Next() {
		var email, password, hash, source string
		if err := rows.Scan(&email, &password, &hash, &source); err != nil {
			continue
		}
		entry := BreachEntry{
			Source:   "local:" + source,
			Name:     source,
			Password: password,
			Hash:     hash,
			Found:    time.Now(),
		}
		entries = append(entries, entry)
	}
	return entries, nil
}

// ─── Main Check Function ──────────────────────────────────────────────────────

// CheckAll runs all breach APIs + local dump for a target.
// Priority: HIBP → LeakCheck → BreachDirectory → IntelX → Local
func CheckAll(target string) BreachResult {
	result := BreachResult{
		Target: target,
		Type:   detectBreachTargetType(target),
	}

	type apiResult struct {
		source  string
		entries []BreachEntry
		err     error
	}

	// Run APIs concurrently
	ch := make(chan apiResult, 5)

	go func() {
		entries, err := CheckHIBP(target)
		ch <- apiResult{"hibp", entries, err}
	}()

	go func() {
		entries, err := CheckLeakCheck(target)
		ch <- apiResult{"leakcheck", entries, err}
	}()

	go func() {
		entries, err := CheckBreachDirectory(target)
		ch <- apiResult{"breachdirectory", entries, err}
	}()

	go func() {
		entries, err := CheckIntelX(target)
		ch <- apiResult{"intelx", entries, err}
	}()

	// Local dump (10% fallback)
	go func() {
		entries, err := SearchLocalDump(target)
		ch <- apiResult{"local", entries, err}
	}()

	// Collect results
	for i := 0; i < 5; i++ {
		r := <-ch
		if r.err == nil && len(r.entries) > 0 {
			result.Breaches = append(result.Breaches, r.entries...)
			result.Sources = append(result.Sources, r.source)
		}
	}

	return result
}

// FormatBreachResult formats breach results for display.
func FormatBreachResult(result BreachResult) string {
	if len(result.Breaches) == 0 {
		return fmt.Sprintf("✓ No breaches found for %s", result.Target)
	}

	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("⚠ BREACHES FOUND for %s (%d total)\n\n", result.Target, len(result.Breaches)))

	for _, b := range result.Breaches {
		sb.WriteString(fmt.Sprintf("  [%s] %s", b.Source, b.Name))
		if b.Date != "" {
			sb.WriteString(fmt.Sprintf(" (%s)", b.Date))
		}
		if b.Count > 0 {
			sb.WriteString(fmt.Sprintf(" — %d records", b.Count))
		}
		if len(b.DataTypes) > 0 {
			sb.WriteString(fmt.Sprintf(" — %s", strings.Join(b.DataTypes, ", ")))
		}
		if b.Password != "" {
			sb.WriteString(fmt.Sprintf(" — PASSWORD: %s", b.Password))
		}
		if b.Hash != "" {
			sb.WriteString(fmt.Sprintf(" — HASH: %s", b.Hash[:min(16, len(b.Hash))]+"..."))
		}
		sb.WriteString("\n")
	}

	return sb.String()
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

func detectBreachTargetType(target string) string {
	if strings.Contains(target, "@") {
		return "email"
	}
	if strings.Contains(target, ".") {
		return "domain"
	}
	return "username"
}

func getLocalDBPath() string {
	home, _ := os.UserHomeDir()
	dir := filepath.Join(home, ".cybermind", "breach")
	os.MkdirAll(dir, 0700)
	return filepath.Join(dir, "breaches.db")
}

func getHIBPKey() string {
	return os.Getenv("HIBP_API_KEY")
}

func getIntelXKey() string {
	return os.Getenv("INTELX_API_KEY")
}

func getBreachDirKey() string {
	return os.Getenv("BREACHDIR_API_KEY")
}

func isHex(s string) bool {
	for _, c := range s {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')) {
			return false
		}
	}
	return true
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
