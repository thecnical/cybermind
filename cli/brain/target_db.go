// brain/target_db.go — SQLite-based Target Knowledge Graph
//
// Every target gets its own SQLite DB at ~/.cybermind/targets/<org>.db
// Tables: assets, endpoints, parameters, findings, js_files, tech_stack, scan_runs
//
// This is the single biggest architectural upgrade:
//   - Every scan writes delta to DB
//   - cybermind diff target.com shows what changed since last run
//   - cybermind /watch target.com monitors daily and pushes Telegram alerts
//   - No more "starting from zero" — every run builds on prior knowledge
//
// Uses pure Go SQLite driver (modernc.org/sqlite) — no CGO needed.
package brain

import (
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	_ "modernc.org/sqlite"
)

// ─── Schema ───────────────────────────────────────────────────────────────────

const targetDBSchema = `
PRAGMA journal_mode=WAL;
PRAGMA foreign_keys=ON;

CREATE TABLE IF NOT EXISTS scan_runs (
	id          INTEGER PRIMARY KEY AUTOINCREMENT,
	run_id      TEXT NOT NULL UNIQUE,
	mode        TEXT NOT NULL DEFAULT 'recon',
	started_at  TEXT NOT NULL,
	finished_at TEXT,
	tools_run   TEXT,  -- comma-separated
	tools_failed TEXT
);

CREATE TABLE IF NOT EXISTS assets (
	id          INTEGER PRIMARY KEY AUTOINCREMENT,
	asset       TEXT NOT NULL UNIQUE,
	asset_type  TEXT NOT NULL DEFAULT 'subdomain', -- subdomain, ip, url
	status      TEXT NOT NULL DEFAULT 'live',      -- live, dead, unknown
	first_seen  TEXT NOT NULL,
	last_seen   TEXT NOT NULL,
	run_id      TEXT NOT NULL,
	ip          TEXT,
	status_code INTEGER,
	server      TEXT,
	title       TEXT,
	tech        TEXT  -- comma-separated
);

CREATE TABLE IF NOT EXISTS endpoints (
	id          INTEGER PRIMARY KEY AUTOINCREMENT,
	url         TEXT NOT NULL UNIQUE,
	method      TEXT NOT NULL DEFAULT 'GET',
	status_code INTEGER,
	content_type TEXT,
	params      TEXT,  -- comma-separated param names
	auth_required INTEGER DEFAULT 0,
	first_seen  TEXT NOT NULL,
	last_seen   TEXT NOT NULL,
	run_id      TEXT NOT NULL,
	source      TEXT   -- tool that found it: katana, gau, waybackurls, etc.
);

CREATE TABLE IF NOT EXISTS parameters (
	id          INTEGER PRIMARY KEY AUTOINCREMENT,
	url         TEXT NOT NULL,
	param       TEXT NOT NULL,
	param_type  TEXT DEFAULT 'query', -- query, body, header, path
	first_seen  TEXT NOT NULL,
	last_seen   TEXT NOT NULL,
	run_id      TEXT NOT NULL,
	UNIQUE(url, param, param_type)
);

CREATE TABLE IF NOT EXISTS js_files (
	id          INTEGER PRIMARY KEY AUTOINCREMENT,
	url         TEXT NOT NULL UNIQUE,
	hash        TEXT,  -- SHA256 of content — detect changes
	endpoints_found INTEGER DEFAULT 0,
	secrets_found   INTEGER DEFAULT 0,
	first_seen  TEXT NOT NULL,
	last_seen   TEXT NOT NULL,
	run_id      TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS findings (
	id          INTEGER PRIMARY KEY AUTOINCREMENT,
	finding_id  TEXT NOT NULL UNIQUE,
	title       TEXT NOT NULL,
	vuln_type   TEXT NOT NULL,  -- xss, sqli, idor, ssrf, rce, etc.
	severity    TEXT NOT NULL,  -- critical, high, medium, low, info
	status      TEXT NOT NULL DEFAULT 'candidate', -- candidate, confirmed, false_positive
	url         TEXT,
	evidence    TEXT,  -- raw tool output line
	tool        TEXT,
	template    TEXT,  -- nuclei template name
	confidence  REAL DEFAULT 0.5,
	human_verified INTEGER DEFAULT 0,
	submitted   INTEGER DEFAULT 0,
	platform    TEXT,  -- hackerone, bugcrowd, intigriti
	report_id   TEXT,
	found_at    TEXT NOT NULL,
	run_id      TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS tech_stack (
	id          INTEGER PRIMARY KEY AUTOINCREMENT,
	tech        TEXT NOT NULL UNIQUE,
	version     TEXT,
	category    TEXT,  -- framework, server, cdn, waf, cms, etc.
	first_seen  TEXT NOT NULL,
	last_seen   TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS diff_log (
	id          INTEGER PRIMARY KEY AUTOINCREMENT,
	run_id      TEXT NOT NULL,
	change_type TEXT NOT NULL,  -- new_asset, removed_asset, new_endpoint, changed_status, new_finding, new_js
	item        TEXT NOT NULL,
	detail      TEXT,
	logged_at   TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_assets_asset ON assets(asset);
CREATE INDEX IF NOT EXISTS idx_endpoints_url ON endpoints(url);
CREATE INDEX IF NOT EXISTS idx_findings_status ON findings(status);
CREATE INDEX IF NOT EXISTS idx_diff_run ON diff_log(run_id);
`

// ─── DB Path ──────────────────────────────────────────────────────────────────

func targetDBPath(target string) string {
	home, _ := os.UserHomeDir()
	safe := strings.NewReplacer(".", "_", "/", "_", ":", "_", " ", "_").Replace(target)
	dir := filepath.Join(home, ".cybermind", "targets")
	os.MkdirAll(dir, 0700)
	return filepath.Join(dir, safe+".db")
}

// openTargetDB opens (or creates) the SQLite DB for a target.
func openTargetDB(target string) (*sql.DB, error) {
	db, err := sql.Open("sqlite", targetDBPath(target)+"?_busy_timeout=5000")
	if err != nil {
		return nil, fmt.Errorf("open target DB: %w", err)
	}
	db.SetMaxOpenConns(1) // SQLite: single writer
	if _, err := db.Exec(targetDBSchema); err != nil {
		db.Close()
		return nil, fmt.Errorf("init schema: %w", err)
	}
	return db, nil
}

// ─── Scan Run ─────────────────────────────────────────────────────────────────

// StartScanRun records the beginning of a scan.
func StartScanRun(target, runID, mode string) error {
	db, err := openTargetDB(target)
	if err != nil { return err }
	defer db.Close()
	_, err = db.Exec(
		`INSERT OR IGNORE INTO scan_runs(run_id, mode, started_at) VALUES(?,?,?)`,
		runID, mode, time.Now().UTC().Format(time.RFC3339),
	)
	return err
}

// FinishScanRun marks a scan as complete.
func FinishScanRun(target, runID string, toolsRun, toolsFailed []string) error {
	db, err := openTargetDB(target)
	if err != nil { return err }
	defer db.Close()
	_, err = db.Exec(
		`UPDATE scan_runs SET finished_at=?, tools_run=?, tools_failed=? WHERE run_id=?`,
		time.Now().UTC().Format(time.RFC3339),
		strings.Join(toolsRun, ","),
		strings.Join(toolsFailed, ","),
		runID,
	)
	return err
}

// ─── Asset Upsert ─────────────────────────────────────────────────────────────

// UpsertAsset adds or updates an asset (subdomain/IP/URL) in the DB.
// Returns true if this is a NEW asset (for diff detection).
func UpsertAsset(target, runID, asset, assetType, status, ip string, statusCode int, server, title, tech string) (isNew bool, err error) {
	db, err := openTargetDB(target)
	if err != nil { return false, err }
	defer db.Close()

	now := time.Now().UTC().Format(time.RFC3339)

	// Check if exists
	var count int
	db.QueryRow(`SELECT COUNT(*) FROM assets WHERE asset=?`, asset).Scan(&count)
	isNew = count == 0

	_, err = db.Exec(`
		INSERT INTO assets(asset, asset_type, status, first_seen, last_seen, run_id, ip, status_code, server, title, tech)
		VALUES(?,?,?,?,?,?,?,?,?,?,?)
		ON CONFLICT(asset) DO UPDATE SET
			status=excluded.status, last_seen=excluded.last_seen, run_id=excluded.run_id,
			ip=excluded.ip, status_code=excluded.status_code, server=excluded.server,
			title=excluded.title, tech=excluded.tech
	`, asset, assetType, status, now, now, runID, ip, statusCode, server, title, tech)

	if isNew && err == nil {
		logDiff(db, runID, "new_asset", asset, fmt.Sprintf("type=%s status=%d", assetType, statusCode))
	}
	return isNew, err
}

// ─── Endpoint Upsert ──────────────────────────────────────────────────────────

// UpsertEndpoint adds or updates an endpoint.
// Returns true if NEW.
func UpsertEndpoint(target, runID, endpointURL, method string, statusCode int, contentType, params, source string) (isNew bool, err error) {
	db, err := openTargetDB(target)
	if err != nil { return false, err }
	defer db.Close()

	now := time.Now().UTC().Format(time.RFC3339)

	var count int
	db.QueryRow(`SELECT COUNT(*) FROM endpoints WHERE url=?`, endpointURL).Scan(&count)
	isNew = count == 0

	_, err = db.Exec(`
		INSERT INTO endpoints(url, method, status_code, content_type, params, first_seen, last_seen, run_id, source)
		VALUES(?,?,?,?,?,?,?,?,?)
		ON CONFLICT(url) DO UPDATE SET
			status_code=excluded.status_code, content_type=excluded.content_type,
			params=excluded.params, last_seen=excluded.last_seen, run_id=excluded.run_id
	`, endpointURL, method, statusCode, contentType, params, now, now, runID, source)

	if isNew && err == nil {
		logDiff(db, runID, "new_endpoint", endpointURL, fmt.Sprintf("method=%s status=%d source=%s", method, statusCode, source))
	}
	return isNew, err
}

// ─── JS File Upsert ───────────────────────────────────────────────────────────

// UpsertJSFile tracks a JS file and detects content changes.
func UpsertJSFile(target, runID, jsURL, hash string, endpointsFound, secretsFound int) (isNew bool, changed bool, err error) {
	db, err := openTargetDB(target)
	if err != nil { return false, false, err }
	defer db.Close()

	now := time.Now().UTC().Format(time.RFC3339)

	var oldHash string
	var count int
	db.QueryRow(`SELECT COUNT(*), COALESCE(hash,'') FROM js_files WHERE url=?`, jsURL).Scan(&count, &oldHash)
	isNew = count == 0
	changed = !isNew && oldHash != "" && oldHash != hash

	_, err = db.Exec(`
		INSERT INTO js_files(url, hash, endpoints_found, secrets_found, first_seen, last_seen, run_id)
		VALUES(?,?,?,?,?,?,?)
		ON CONFLICT(url) DO UPDATE SET
			hash=excluded.hash, endpoints_found=excluded.endpoints_found,
			secrets_found=excluded.secrets_found, last_seen=excluded.last_seen, run_id=excluded.run_id
	`, jsURL, hash, endpointsFound, secretsFound, now, now, runID)

	if isNew && err == nil {
		logDiff(db, runID, "new_js", jsURL, fmt.Sprintf("endpoints=%d secrets=%d", endpointsFound, secretsFound))
	} else if changed && err == nil {
		logDiff(db, runID, "changed_js", jsURL, fmt.Sprintf("hash changed: %s→%s", oldHash[:8], hash[:8]))
	}
	return isNew, changed, err
}

// ─── Finding Upsert ───────────────────────────────────────────────────────────

// UpsertFinding adds a finding with evidence citation.
// Status is always "candidate" — never auto-confirmed.
func UpsertFinding(target, runID string, f FindingRecord) error {
	db, err := openTargetDB(target)
	if err != nil { return err }
	defer db.Close()

	now := time.Now().UTC().Format(time.RFC3339)
	if f.FoundAt == "" { f.FoundAt = now }
	if f.Status == "" { f.Status = "candidate" }
	// NEVER auto-set to "confirmed" — requires human_verified=1
	if f.Status == "confirmed" && f.HumanVerified == 0 {
		f.Status = "candidate"
	}

	_, err = db.Exec(`
		INSERT INTO findings(finding_id, title, vuln_type, severity, status, url, evidence, tool, template, confidence, human_verified, found_at, run_id)
		VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)
		ON CONFLICT(finding_id) DO UPDATE SET
			status=excluded.status, evidence=excluded.evidence, confidence=excluded.confidence
	`, f.FindingID, f.Title, f.VulnType, f.Severity, f.Status, f.URL,
		f.Evidence, f.Tool, f.Template, f.Confidence, f.HumanVerified, f.FoundAt, runID)

	if err == nil {
		logDiff(db, runID, "new_finding", f.Title, fmt.Sprintf("severity=%s url=%s tool=%s", f.Severity, f.URL, f.Tool))
	}
	return err
}

// FindingRecord is the structured finding schema — every field must be cited.
type FindingRecord struct {
	FindingID     string  `json:"finding_id"`
	Title         string  `json:"title"`
	VulnType      string  `json:"vuln_type"`
	Severity      string  `json:"severity"`
	Status        string  `json:"status"`        // always "candidate" unless human_verified=1
	URL           string  `json:"url"`
	Evidence      string  `json:"evidence"`      // raw tool output line — REQUIRED
	Tool          string  `json:"tool"`          // which tool found it — REQUIRED
	Template      string  `json:"template"`      // nuclei template if applicable
	Confidence    float64 `json:"confidence"`    // 0.0-1.0
	HumanVerified int     `json:"human_verified"` // 0 or 1 — only human can set to 1
	FoundAt       string  `json:"found_at"`
}

// ─── Diff Engine ──────────────────────────────────────────────────────────────

// DiffResult holds what changed since the last scan run.
type DiffResult struct {
	Target        string
	RunID         string
	PrevRunID     string
	NewAssets     []string
	RemovedAssets []string
	NewEndpoints  []string
	ChangedJS     []string
	NewFindings   []FindingRecord
	NewJSFiles    []string
	TotalNew      int
	TotalChanged  int
	GeneratedAt   time.Time
}

// GetDiff returns what changed in the latest run vs the previous run.
func GetDiff(target, currentRunID string) (*DiffResult, error) {
	db, err := openTargetDB(target)
	if err != nil { return nil, err }
	defer db.Close()

	result := &DiffResult{
		Target:      target,
		RunID:       currentRunID,
		GeneratedAt: time.Now(),
	}

	// Get all diff log entries for this run
	rows, err := db.Query(`
		SELECT change_type, item, detail FROM diff_log
		WHERE run_id=? ORDER BY logged_at ASC
	`, currentRunID)
	if err != nil { return result, nil }
	defer rows.Close()

	for rows.Next() {
		var changeType, item, detail string
		rows.Scan(&changeType, &item, &detail)
		switch changeType {
		case "new_asset":
			result.NewAssets = append(result.NewAssets, item)
		case "new_endpoint":
			result.NewEndpoints = append(result.NewEndpoints, item)
		case "new_js":
			result.NewJSFiles = append(result.NewJSFiles, item)
		case "changed_js":
			result.ChangedJS = append(result.ChangedJS, item+" ("+detail+")")
		}
	}

	result.TotalNew = len(result.NewAssets) + len(result.NewEndpoints) + len(result.NewJSFiles)
	result.TotalChanged = len(result.ChangedJS)
	return result, nil
}

// FormatDiffOutput formats a DiffResult for terminal display.
func FormatDiffOutput(d *DiffResult) string {
	if d.TotalNew == 0 && d.TotalChanged == 0 && len(d.NewFindings) == 0 {
		return fmt.Sprintf("  ✓ No changes detected for %s since last scan\n", d.Target)
	}

	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("\n  📊 DIFF — %s\n", d.Target))
	sb.WriteString(fmt.Sprintf("  %s\n\n", strings.Repeat("─", 60)))

	if len(d.NewAssets) > 0 {
		sb.WriteString(fmt.Sprintf("  [+] NEW ASSETS (%d)\n", len(d.NewAssets)))
		for _, a := range d.NewAssets {
			sb.WriteString(fmt.Sprintf("      + %s\n", a))
		}
		sb.WriteString("\n")
	}

	if len(d.NewEndpoints) > 0 {
		limit := len(d.NewEndpoints)
		if limit > 20 { limit = 20 }
		sb.WriteString(fmt.Sprintf("  [+] NEW ENDPOINTS (%d)\n", len(d.NewEndpoints)))
		for _, e := range d.NewEndpoints[:limit] {
			sb.WriteString(fmt.Sprintf("      + %s\n", e))
		}
		if len(d.NewEndpoints) > 20 {
			sb.WriteString(fmt.Sprintf("      ... and %d more\n", len(d.NewEndpoints)-20))
		}
		sb.WriteString("\n")
	}

	if len(d.NewJSFiles) > 0 {
		sb.WriteString(fmt.Sprintf("  [+] NEW JS FILES (%d)\n", len(d.NewJSFiles)))
		for _, j := range d.NewJSFiles {
			sb.WriteString(fmt.Sprintf("      + %s\n", j))
		}
		sb.WriteString("\n")
	}

	if len(d.ChangedJS) > 0 {
		sb.WriteString(fmt.Sprintf("  [~] CHANGED JS FILES (%d)\n", len(d.ChangedJS)))
		for _, j := range d.ChangedJS {
			sb.WriteString(fmt.Sprintf("      ~ %s\n", j))
		}
		sb.WriteString("\n")
	}

	if len(d.NewFindings) > 0 {
		sb.WriteString(fmt.Sprintf("  [!] NEW FINDINGS (%d)\n", len(d.NewFindings)))
		for _, f := range d.NewFindings {
			sb.WriteString(fmt.Sprintf("      ! [%s] %s — %s\n", strings.ToUpper(f.Severity), f.Title, f.URL))
		}
		sb.WriteString("\n")
	}

	sb.WriteString(fmt.Sprintf("  Total: +%d new, ~%d changed\n", d.TotalNew, d.TotalChanged))
	return sb.String()
}

// ─── Hotlist ──────────────────────────────────────────────────────────────────

// HotlistDBEntry is a high-value target from the DB.
type HotlistDBEntry struct {
	Asset       string
	Score       float64
	Reason      string
	Endpoints   int
	Findings    int
	NewSince    string
}

// GetHotlistFromDB returns top assets ranked by attack surface score.
func GetHotlistFromDB(target string, limit int) ([]HotlistDBEntry, error) {
	db, err := openTargetDB(target)
	if err != nil { return nil, err }
	defer db.Close()

	rows, err := db.Query(`
		SELECT
			a.asset,
			COUNT(DISTINCT e.url) as endpoint_count,
			COUNT(DISTINCT f.id) as finding_count,
			a.tech,
			a.status_code,
			a.first_seen
		FROM assets a
		LEFT JOIN endpoints e ON e.url LIKE '%' || a.asset || '%'
		LEFT JOIN findings f ON f.url LIKE '%' || a.asset || '%'
		WHERE a.status = 'live'
		GROUP BY a.asset
		ORDER BY finding_count DESC, endpoint_count DESC
		LIMIT ?
	`, limit)
	if err != nil { return nil, err }
	defer rows.Close()

	var entries []HotlistDBEntry
	for rows.Next() {
		var e HotlistDBEntry
		var tech string
		var statusCode int
		rows.Scan(&e.Asset, &e.Endpoints, &e.Findings, &tech, &statusCode, &e.NewSince)

		// Score calculation
		e.Score = float64(e.Findings)*30 + float64(e.Endpoints)*2
		if strings.Contains(tech, "admin") || strings.Contains(e.Asset, "admin") { e.Score += 20 }
		if strings.Contains(e.Asset, "api") || strings.Contains(e.Asset, "internal") { e.Score += 15 }
		if strings.Contains(tech, "wordpress") || strings.Contains(tech, "drupal") { e.Score += 10 }
		if statusCode == 200 { e.Score += 5 }

		e.Reason = fmt.Sprintf("%d endpoints, %d findings", e.Endpoints, e.Findings)
		if tech != "" { e.Reason += ", tech: " + tech }
		entries = append(entries, e)
	}
	return entries, nil
}

// ─── Stats ────────────────────────────────────────────────────────────────────

// GetTargetStats returns summary stats for a target.
func GetTargetStats(target string) (assets, endpoints, findings, jsFiles int, lastScan string, err error) {
	db, err := openTargetDB(target)
	if err != nil { return }
	defer db.Close()

	db.QueryRow(`SELECT COUNT(*) FROM assets WHERE status='live'`).Scan(&assets)
	db.QueryRow(`SELECT COUNT(*) FROM endpoints`).Scan(&endpoints)
	db.QueryRow(`SELECT COUNT(*) FROM findings WHERE status != 'false_positive'`).Scan(&findings)
	db.QueryRow(`SELECT COUNT(*) FROM js_files`).Scan(&jsFiles)
	db.QueryRow(`SELECT COALESCE(MAX(started_at),'never') FROM scan_runs`).Scan(&lastScan)
	return
}

// ListTrackedTargets returns all targets that have a DB.
func ListTrackedTargets() []string {
	home, _ := os.UserHomeDir()
	dir := filepath.Join(home, ".cybermind", "targets")
	entries, err := os.ReadDir(dir)
	if err != nil { return nil }

	var targets []string
	for _, e := range entries {
		if strings.HasSuffix(e.Name(), ".db") {
			name := strings.TrimSuffix(e.Name(), ".db")
			// Reverse the safe name back to domain
			name = strings.ReplaceAll(name, "_", ".")
			targets = append(targets, name)
		}
	}
	return targets
}

// ─── Internal helpers ─────────────────────────────────────────────────────────

func logDiff(db *sql.DB, runID, changeType, item, detail string) {
	db.Exec(`
		INSERT INTO diff_log(run_id, change_type, item, detail, logged_at)
		VALUES(?,?,?,?,?)
	`, runID, changeType, item, detail, time.Now().UTC().Format(time.RFC3339))
}
