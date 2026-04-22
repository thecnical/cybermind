// Package breach — CyberMind Breach Intelligence Module
// Sources:
//   1. HIBP v3 (Have I Been Pwned) — free + paid key
//   2. BreachDirectory via RapidAPI — X-RapidAPI-Key
//   3. LeakCheck.io — free public API
//   4. WhatsApp OSINT via RapidAPI — phone number intelligence
//   5. Local SQLite — user-indexed breach dumps
//
// RapidAPI Key stored in: ~/.cybermind/config.json → rapidapi_key
// Or env: RAPIDAPI_KEY
package breach

import (
	"bufio"
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
	Type     string // "email" | "domain" | "phone"
	Breaches []BreachEntry
	Sources  []string
	Error    string
}

// BreachEntry is a single breach record.
type BreachEntry struct {
	Source    string
	Name      string
	Date      string
	Count     int64
	DataTypes []string
	Password  string
	Hash      string
	Found     time.Time
}

// WhatsAppInfo holds WhatsApp OSINT results for a phone number.
type WhatsAppInfo struct {
	Phone    string
	Name     string
	About    string
	Photo    string
	Business bool
	Found    bool
}

var httpClient = &http.Client{Timeout: 10 * time.Second}

// ─── Key Management ───────────────────────────────────────────────────────────

// GetRapidAPIKey returns RapidAPI key from env or config file.
func GetRapidAPIKey() string {
	if k := os.Getenv("RAPIDAPI_KEY"); k != "" {
		return k
	}
	home, _ := os.UserHomeDir()
	data, err := os.ReadFile(filepath.Join(home, ".cybermind", "config.json"))
	if err != nil {
		return ""
	}
	var cfg map[string]interface{}
	if json.Unmarshal(data, &cfg) == nil {
		if k, ok := cfg["rapidapi_key"].(string); ok {
			return k
		}
	}
	return ""
}

// SaveRapidAPIKey saves RapidAPI key to config file.
func SaveRapidAPIKey(key string) error {
	home, _ := os.UserHomeDir()
	dir := filepath.Join(home, ".cybermind")
	os.MkdirAll(dir, 0700)
	cfgPath := filepath.Join(dir, "config.json")

	var cfg map[string]interface{}
	data, err := os.ReadFile(cfgPath)
	if err == nil {
		json.Unmarshal(data, &cfg)
	}
	if cfg == nil {
		cfg = make(map[string]interface{})
	}
	cfg["rapidapi_key"] = key
	updated, _ := json.MarshalIndent(cfg, "", "  ")
	return os.WriteFile(cfgPath, updated, 0600)
}

func getHIBPKey() string {
	return os.Getenv("HIBP_API_KEY")
}

// ─── 1. HIBP v3 ───────────────────────────────────────────────────────────────

// CheckHIBP queries Have I Been Pwned v3 API.
// Free tier: breach names only. Paid key: full details.
func CheckHIBP(email string) ([]BreachEntry, error) {
	if !strings.Contains(email, "@") {
		return nil, nil
	}

	reqURL := fmt.Sprintf("https://haveibeenpwned.com/api/v3/breachedaccount/%s?truncateResponse=false",
		url.PathEscape(email))

	req, err := http.NewRequest("GET", reqURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "CyberMind-OSINT/1.0")
	if k := getHIBPKey(); k != "" {
		req.Header.Set("hibp-api-key", k)
	}

	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode == 404 {
		return nil, nil // clean — not found
	}
	if resp.StatusCode == 401 {
		// No key — try without truncation flag
		return checkHIBPBasic(email)
	}
	if resp.StatusCode == 429 {
		return nil, fmt.Errorf("HIBP rate limited — wait 1.5s between requests")
	}
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("HIBP: %d", resp.StatusCode)
	}

	body, _ := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
	var raw []map[string]interface{}
	if json.Unmarshal(body, &raw) != nil {
		return nil, nil
	}

	var entries []BreachEntry
	for _, b := range raw {
		e := BreachEntry{Source: "hibp", Found: time.Now()}
		if v, ok := b["Name"].(string); ok {
			e.Name = v
		}
		if v, ok := b["BreachDate"].(string); ok {
			e.Date = v
		}
		if v, ok := b["PwnCount"].(float64); ok {
			e.Count = int64(v)
		}
		if types, ok := b["DataClasses"].([]interface{}); ok {
			for _, t := range types {
				if s, ok := t.(string); ok {
					e.DataTypes = append(e.DataTypes, s)
				}
			}
		}
		entries = append(entries, e)
	}
	return entries, nil
}

func checkHIBPBasic(email string) ([]BreachEntry, error) {
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
		return nil, fmt.Errorf("HIBP basic: %d", resp.StatusCode)
	}

	body, _ := io.ReadAll(io.LimitReader(resp.Body, 32*1024))
	var raw []map[string]interface{}
	if json.Unmarshal(body, &raw) != nil {
		return nil, nil
	}

	var entries []BreachEntry
	for _, b := range raw {
		e := BreachEntry{Source: "hibp", Found: time.Now()}
		if v, ok := b["Name"].(string); ok {
			e.Name = v
		}
		entries = append(entries, e)
	}
	return entries, nil
}

// ─── 2. BreachDirectory via RapidAPI ─────────────────────────────────────────

// CheckBreachDirectory queries BreachDirectory via RapidAPI.
// Requires RapidAPI key. Returns emails, passwords, hashes.
func CheckBreachDirectory(target string) ([]BreachEntry, error) {
	key := GetRapidAPIKey()
	if key == "" {
		return nil, fmt.Errorf("RapidAPI key not set — run: cybermind /breach --setup")
	}

	reqURL := fmt.Sprintf("https://breachdirectory.p.rapidapi.com/?func=auto&term=%s",
		url.QueryEscape(target))

	req, err := http.NewRequest("GET", reqURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("X-RapidAPI-Key", key)
	req.Header.Set("X-RapidAPI-Host", "breachdirectory.p.rapidapi.com")
	req.Header.Set("Content-Type", "application/json")

	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode == 403 || resp.StatusCode == 401 {
		return nil, fmt.Errorf("BreachDirectory: invalid RapidAPI key")
	}
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("BreachDirectory: %d", resp.StatusCode)
	}

	body, _ := io.ReadAll(io.LimitReader(resp.Body, 64*1024))

	var result struct {
		Success bool `json:"success"`
		Found   int  `json:"found"`
		Result  []struct {
			Email    string   `json:"email"`
			Password string   `json:"password"`
			SHA1     string   `json:"sha1"`
			Hash     string   `json:"hash"`
			Sources  []string `json:"sources"`
		} `json:"result"`
	}

	if json.Unmarshal(body, &result) != nil {
		return nil, nil
	}
	if !result.Success || result.Found == 0 {
		return nil, nil
	}

	var entries []BreachEntry
	for _, r := range result.Result {
		e := BreachEntry{
			Source: "breachdirectory",
			Found:  time.Now(),
		}
		if len(r.Sources) > 0 {
			e.Name = strings.Join(r.Sources, ", ")
		}
		if r.Password != "" {
			e.Password = r.Password
		}
		if r.SHA1 != "" {
			e.Hash = r.SHA1
		} else if r.Hash != "" {
			e.Hash = r.Hash
		}
		entries = append(entries, e)
	}
	return entries, nil
}

// ─── 3. LeakCheck.io ─────────────────────────────────────────────────────────

// CheckLeakCheck queries LeakCheck.io free public API.
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
		return nil, fmt.Errorf("LeakCheck: %d", resp.StatusCode)
	}

	body, _ := io.ReadAll(io.LimitReader(resp.Body, 32*1024))

	var result struct {
		Success bool `json:"success"`
		Found   int  `json:"found"`
		Sources []struct {
			Name string `json:"name"`
			Date string `json:"date"`
		} `json:"sources"`
	}

	if json.Unmarshal(body, &result) != nil {
		return nil, nil
	}
	if !result.Success || result.Found == 0 {
		return nil, nil
	}

	var entries []BreachEntry
	for _, s := range result.Sources {
		entries = append(entries, BreachEntry{
			Source: "leakcheck",
			Name:   s.Name,
			Date:   s.Date,
			Found:  time.Now(),
		})
	}
	return entries, nil
}

// ─── 4. WhatsApp OSINT via RapidAPI ──────────────────────────────────────────

// CheckWhatsApp queries WhatsApp OSINT API for phone number intelligence.
// Returns name, about, profile photo, business status.
func CheckWhatsApp(phone string) (*WhatsAppInfo, error) {
	key := GetRapidAPIKey()
	if key == "" {
		return nil, fmt.Errorf("RapidAPI key not set")
	}

	// Clean phone number — remove spaces, dashes, keep + and digits
	clean := strings.Map(func(r rune) rune {
		if r >= '0' && r <= '9' || r == '+' {
			return r
		}
		return -1
	}, phone)

	if len(clean) < 10 {
		return nil, fmt.Errorf("invalid phone number: %s", phone)
	}

	// WhatsApp OSINT API — Business Insights endpoint
	reqURL := "https://whatsapp-osint.p.rapidapi.com/bios"
	payload := fmt.Sprintf(`{"phone":"%s"}`, clean)

	req, err := http.NewRequest("POST", reqURL, strings.NewReader(payload))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-RapidAPI-Key", key)
	req.Header.Set("X-RapidAPI-Host", "whatsapp-osint.p.rapidapi.com")

	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode == 403 || resp.StatusCode == 401 {
		return nil, fmt.Errorf("WhatsApp OSINT: invalid RapidAPI key")
	}
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("WhatsApp OSINT: %d", resp.StatusCode)
	}

	body, _ := io.ReadAll(io.LimitReader(resp.Body, 32*1024))

	var result map[string]interface{}
	if json.Unmarshal(body, &result) != nil {
		return nil, nil
	}

	info := &WhatsAppInfo{Phone: clean}

	// Parse response fields
	if name, ok := result["name"].(string); ok && name != "" {
		info.Name = name
		info.Found = true
	}
	if about, ok := result["about"].(string); ok {
		info.About = about
	}
	if photo, ok := result["photo"].(string); ok {
		info.Photo = photo
	}
	if biz, ok := result["isBusiness"].(bool); ok {
		info.Business = biz
	}
	// Some APIs return status field
	if status, ok := result["status"].(string); ok && status != "" {
		info.About = status
		info.Found = true
	}

	return info, nil
}

// CheckWhatsAppFetchOSINT uses the "Fetch osint info" endpoint.
func CheckWhatsAppFetchOSINT(phone string) (string, error) {
	key := GetRapidAPIKey()
	if key == "" {
		return "", fmt.Errorf("RapidAPI key not set")
	}

	clean := strings.Map(func(r rune) rune {
		if r >= '0' && r <= '9' || r == '+' {
			return r
		}
		return -1
	}, phone)

	reqURL := fmt.Sprintf("https://whatsapp-osint.p.rapidapi.com/osint?phone=%s", url.QueryEscape(clean))

	req, err := http.NewRequest("GET", reqURL, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("X-RapidAPI-Key", key)
	req.Header.Set("X-RapidAPI-Host", "whatsapp-osint.p.rapidapi.com")

	resp, err := httpClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return "", fmt.Errorf("WhatsApp OSINT fetch: %d", resp.StatusCode)
	}

	body, _ := io.ReadAll(io.LimitReader(resp.Body, 32*1024))
	return string(body), nil
}

// ─── 5. Local SQLite Dump ─────────────────────────────────────────────────────

// IndexLocalDump indexes a breach dump file into SQLite.
// Supports: email:password, email:hash, plain email lists.
// Large files (100M+ lines) handled via streaming + batch inserts.
func IndexLocalDump(dumpPath string) error {
	dbPath := GetLocalDBPath()
	db, err := sql.Open("sqlite3", dbPath+"?_journal_mode=WAL&_synchronous=NORMAL")
	if err != nil {
		return fmt.Errorf("open db: %v", err)
	}
	defer db.Close()

	_, err = db.Exec(`CREATE TABLE IF NOT EXISTS breaches (
		id       INTEGER PRIMARY KEY AUTOINCREMENT,
		email    TEXT NOT NULL,
		password TEXT,
		hash     TEXT,
		source   TEXT,
		indexed  DATETIME DEFAULT CURRENT_TIMESTAMP
	)`)
	if err != nil {
		return fmt.Errorf("create table: %v", err)
	}
	_, _ = db.Exec(`CREATE INDEX IF NOT EXISTS idx_email ON breaches(email)`)

	source := filepath.Base(dumpPath)

	// Stream file line by line — handles huge dumps without OOM
	f, err := os.Open(dumpPath)
	if err != nil {
		return fmt.Errorf("open dump: %v", err)
	}
	defer f.Close()

	tx, _ := db.Begin()
	stmt, _ := tx.Prepare(`INSERT OR IGNORE INTO breaches (email, password, hash, source) VALUES (?, ?, ?, ?)`)

	count := 0
	skipped := 0
	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 1024*1024), 1024*1024) // 1MB line buffer

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		var email, password, hash string

		if strings.Contains(line, ":") {
			parts := strings.SplitN(line, ":", 2)
			email = strings.ToLower(strings.TrimSpace(parts[0]))
			val := strings.TrimSpace(parts[1])
			if len(val) >= 32 && isHex(val) {
				hash = val
			} else {
				password = val
			}
		} else if strings.Contains(line, "@") {
			email = strings.ToLower(strings.TrimSpace(line))
		} else {
			skipped++
			continue
		}

		if !strings.Contains(email, "@") || len(email) > 254 {
			skipped++
			continue
		}

		stmt.Exec(email, password, hash, source)
		count++

		// Commit every 50K records
		if count%50000 == 0 {
			stmt.Close()
			tx.Commit()
			fmt.Printf("\r  ⟳ Indexed %d records...", count)
			tx, _ = db.Begin()
			stmt, _ = tx.Prepare(`INSERT OR IGNORE INTO breaches (email, password, hash, source) VALUES (?, ?, ?, ?)`)
		}
	}

	stmt.Close()
	tx.Commit()

	fmt.Printf("\r  ✓ Indexed %d records from %s (%d skipped)\n", count, source, skipped)
	return scanner.Err()
}

// SearchLocalDump searches the local SQLite breach database.
func SearchLocalDump(target string) ([]BreachEntry, error) {
	dbPath := GetLocalDBPath()
	if _, err := os.Stat(dbPath); err != nil {
		return nil, nil
	}

	db, err := sql.Open("sqlite3", dbPath+"?_journal_mode=WAL")
	if err != nil {
		return nil, err
	}
	defer db.Close()

	var query string
	var args []interface{}

	if strings.Contains(target, "@") && !strings.HasPrefix(target, "@") {
		query = `SELECT email, password, hash, source FROM breaches WHERE email = ? LIMIT 50`
		args = []interface{}{strings.ToLower(target)}
	} else if strings.HasPrefix(target, "@") || strings.Contains(target, ".") {
		domain := strings.TrimPrefix(target, "@")
		query = `SELECT email, password, hash, source FROM breaches WHERE email LIKE ? LIMIT 100`
		args = []interface{}{"%" + domain}
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
		if rows.Scan(&email, &password, &hash, &source) != nil {
			continue
		}
		entries = append(entries, BreachEntry{
			Source:   "local:" + source,
			Name:     source,
			Password: password,
			Hash:     hash,
			Found:    time.Now(),
		})
	}
	return entries, nil
}

// GetLocalDBStats returns stats about the local breach database.
func GetLocalDBStats() (totalRecords int64, sources []string, err error) {
	dbPath := GetLocalDBPath()
	if _, err := os.Stat(dbPath); err != nil {
		return 0, nil, nil
	}

	db, err := sql.Open("sqlite3", dbPath)
	if err != nil {
		return 0, nil, err
	}
	defer db.Close()

	db.QueryRow(`SELECT COUNT(*) FROM breaches`).Scan(&totalRecords)

	rows, _ := db.Query(`SELECT DISTINCT source FROM breaches ORDER BY source`)
	if rows != nil {
		defer rows.Close()
		for rows.Next() {
			var s string
			if rows.Scan(&s) == nil {
				sources = append(sources, s)
			}
		}
	}
	return totalRecords, sources, nil
}

// ─── Main Check Function ──────────────────────────────────────────────────────

// CheckAll runs all breach sources concurrently for a target.
// Priority: HIBP → BreachDirectory (RapidAPI) → LeakCheck → Local
func CheckAll(target string) BreachResult {
	result := BreachResult{
		Target: target,
		Type:   DetectTargetType(target),
	}

	type apiResult struct {
		source  string
		entries []BreachEntry
		err     error
	}

	ch := make(chan apiResult, 4)

	// 1. HIBP
	go func() {
		entries, err := CheckHIBP(target)
		ch <- apiResult{"hibp", entries, err}
	}()

	// 2. BreachDirectory via RapidAPI
	go func() {
		entries, err := CheckBreachDirectory(target)
		ch <- apiResult{"breachdirectory", entries, err}
	}()

	// 3. LeakCheck free
	go func() {
		entries, err := CheckLeakCheck(target)
		ch <- apiResult{"leakcheck", entries, err}
	}()

	// 4. Local SQLite
	go func() {
		entries, err := SearchLocalDump(target)
		ch <- apiResult{"local", entries, err}
	}()

	for i := 0; i < 4; i++ {
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
	sb.WriteString(fmt.Sprintf("⚠ BREACHES FOUND for %s (%d records)\n\n", result.Target, len(result.Breaches)))

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
			h := b.Hash
			if len(h) > 16 {
				h = h[:16] + "..."
			}
			sb.WriteString(fmt.Sprintf(" — HASH: %s", h))
		}
		sb.WriteString("\n")
	}
	return sb.String()
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

// DetectTargetType returns "email", "domain", or "phone".
func DetectTargetType(target string) string {
	if strings.HasPrefix(target, "+") {
		return "phone"
	}
	if strings.Contains(target, "@") {
		return "email"
	}
	return "domain"
}

// GetLocalDBPath returns path to local breach SQLite database.
func GetLocalDBPath() string {
	home, _ := os.UserHomeDir()
	dir := filepath.Join(home, ".cybermind", "breach")
	os.MkdirAll(dir, 0700)
	return filepath.Join(dir, "breaches.db")
}

func isHex(s string) bool {
	for _, c := range s {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')) {
			return false
		}
	}
	return true
}

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}
