// Package locate — CyberMind Deep Geolocation Mode
// Linux-only. Multi-level geolocation from basic IP to SDR cell tower tracking.
//
// Usage:
//   cybermind /locate <target>                 — auto-detect, all levels
//   cybermind /locate-advanced <target>        — Level 5 SDR/cell tower (needs hardware)
//
// Levels:
//   Level 1 — IP/Domain Geolocation (geoiplookup, ipinfo, shodan)
//   Level 2 — EXIF / Metadata GPS (exiftool, FOCA, metagoofil)
//   Level 3 — WiFi / Network (tshark, kismet)
//   Level 4 — Social Geolocation (Creepy, osintgram, twscrape)
//   Level 5 — Cell Tower / SDR (gr-gsm, srsRAN, YateBTS, OpenCellID, SigPloit)
package locate

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"regexp"
	"strings"
	"time"
)

// ─── Types ────────────────────────────────────────────────────────────────────

type LocateResult struct {
	Target  string
	Results []LocateToolResult
	Tools   []string
	Failed  []LocateToolResult
	Skipped []LocateSkipped
	Context *LocateContext
}

type LocateToolResult struct {
	Tool    string
	Output  string
	Error   string
	Partial bool
	Took    time.Duration
}

type LocateSkipped struct {
	Tool        string
	Reason      string
	InstallHint string
}

type LocateStatusKind string

const (
	LocateRunning     LocateStatusKind = "running"
	LocateDone        LocateStatusKind = "done"
	LocateFailed      LocateStatusKind = "failed"
	LocateKindSkipped LocateStatusKind = "skipped"
	LocatePartial     LocateStatusKind = "partial"
	LocateRetry       LocateStatusKind = "retry"
)

type LocateStatus struct {
	Tool   string
	Kind   LocateStatusKind
	Reason string
	Took   time.Duration
}

type LocateContext struct {
	Target     string
	TargetType string // "ip"|"domain"|"phone"|"file"|"username"
	Advanced   bool   // Level 5 SDR mode

	// Findings
	IPAddresses   []string
	Coordinates   []string // "lat,lon" pairs
	City          string
	Country       string
	ISP           string
	ASN           string
	ExifGPS       string
	WiFiSSIDs     []string
	CellTowers    []string
	SocialGeo     []string

	// Session
	SessionDir string
	StartedAt  time.Time
}

type LocateSession struct {
	Target      string    `json:"target"`
	TargetType  string    `json:"target_type"`
	StartedAt   time.Time `json:"started_at"`
	Coordinates []string  `json:"coordinates"`
	City        string    `json:"city"`
	Country     string    `json:"country"`
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

var ansiReLocate = regexp.MustCompile(`\x1b\[[0-9;]*[a-zA-Z]`)

func sanitizeLocate(s string, maxLen int) string {
	clean := ansiReLocate.ReplaceAllString(s, "")
	if len(clean) > maxLen {
		return clean[:maxLen] + "\n... [truncated]"
	}
	return clean
}

// DetectLocateTargetType auto-detects the type of locate target from input.
func DetectLocateTargetType(target string) string {
	return detectLocateTargetType(target)
}

func detectLocateTargetType(target string) string {
	if net.ParseIP(target) != nil {
		return "ip"
	}
	if strings.HasPrefix(target, "+") {
		return "phone"
	}
	if strings.HasPrefix(target, "/") || strings.HasSuffix(target, ".jpg") ||
		strings.HasSuffix(target, ".jpeg") || strings.HasSuffix(target, ".png") {
		return "file"
	}
	if strings.Contains(target, ".") {
		return "domain"
	}
	return "username"
}

func run(timeoutSec int, name string, args ...string) (string, error) {
	cmd := exec.Command(name, args...)
	var out bytes.Buffer
	var errOut bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &errOut
	cmd.Stdin = nil

	done := make(chan error, 1)
	go func() { done <- cmd.Run() }()

	select {
	case err := <-done:
		combined := out.String()
		if combined == "" {
			combined = errOut.String()
		}
		if err != nil && combined == "" {
			return "", err
		}
		return combined, nil
	case <-time.After(time.Duration(timeoutSec) * time.Second):
		if cmd.Process != nil {
			cmd.Process.Kill()
		}
		partial := out.String()
		if partial != "" {
			return partial + "\n[timeout]", nil
		}
		return "", fmt.Errorf("timeout after %ds", timeoutSec)
	}
}

func runShell(timeoutSec int, shellCmd string) (string, error) {
	return run(timeoutSec, "bash", "-c", shellCmd)
}

// ipinfoLookup queries ipinfo.io free API for IP geolocation.
func ipinfoLookup(ip string) string {
	client := &http.Client{Timeout: 8 * time.Second}
	resp, err := client.Get("https://ipinfo.io/" + ip + "/json")
	if err != nil || resp.StatusCode != 200 {
		return ""
	}
	defer resp.Body.Close()
	var data map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&data); err != nil {
		return ""
	}
	var parts []string
	for _, key := range []string{"ip", "city", "region", "country", "org", "loc", "timezone"} {
		if v, ok := data[key]; ok {
			parts = append(parts, fmt.Sprintf("%s: %v", key, v))
		}
	}
	return strings.Join(parts, " | ")
}

// opencellIDLookup queries OpenCellID API for cell tower location.
func opencellIDLookup(mcc, mnc, lac, cellID string) string {
	client := &http.Client{Timeout: 8 * time.Second}
	url := fmt.Sprintf("https://opencellid.org/cell/get?key=test&mcc=%s&mnc=%s&lac=%s&cellid=%s&format=json",
		mcc, mnc, lac, cellID)
	resp, err := client.Get(url)
	if err != nil || resp.StatusCode != 200 {
		return ""
	}
	defer resp.Body.Close()
	var data map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&data); err != nil {
		return ""
	}
	if lat, ok := data["lat"]; ok {
		if lon, ok2 := data["lon"]; ok2 {
			return fmt.Sprintf("Cell Tower GPS: %v,%v", lat, lon)
		}
	}
	return ""
}

// updateLocateContext enriches context from tool output.
func updateLocateContext(tool, output string, ctx *LocateContext) {
	switch tool {
	case "geoiplookup", "ipinfo":
		for _, line := range strings.Split(output, "\n") {
			if strings.Contains(line, "city:") || strings.Contains(line, "City:") {
				ctx.City = strings.TrimSpace(strings.SplitN(line, ":", 2)[1])
			}
			if strings.Contains(line, "country:") || strings.Contains(line, "Country:") {
				ctx.Country = strings.TrimSpace(strings.SplitN(line, ":", 2)[1])
			}
			if strings.Contains(line, "org:") || strings.Contains(line, "ISP:") {
				ctx.ISP = strings.TrimSpace(strings.SplitN(line, ":", 2)[1])
			}
			if strings.Contains(line, "loc:") {
				ctx.Coordinates = append(ctx.Coordinates, strings.TrimSpace(strings.SplitN(line, ":", 2)[1]))
			}
		}
	case "exiftool":
		for _, line := range strings.Split(output, "\n") {
			if strings.Contains(line, "GPS") && strings.Contains(line, ":") {
				ctx.ExifGPS += strings.TrimSpace(line) + "\n"
			}
		}
	case "tshark", "kismet":
		for _, line := range strings.Split(output, "\n") {
			if strings.Contains(line, "SSID") || strings.Contains(line, "ssid") {
				ctx.WiFiSSIDs = append(ctx.WiFiSSIDs, strings.TrimSpace(line))
			}
		}
	case "grgsm_livemon":
		for _, line := range strings.Split(output, "\n") {
			if strings.Contains(line, "IMSI") || strings.Contains(line, "LAC") || strings.Contains(line, "CellID") {
				ctx.CellTowers = append(ctx.CellTowers, strings.TrimSpace(line))
			}
		}
	}
}

// ─── Tool Detection ───────────────────────────────────────────────────────────

var lookPathLocate = exec.LookPath

func detectLocateTools(requested []string, advanced bool) (available []LocateToolSpec, skipped []LocateSkipped, err error) {
	for _, spec := range locateRegistry {
		// Skip Level 5 tools unless advanced mode
		if spec.Level == 5 && !advanced {
			skipped = append(skipped, LocateSkipped{
				Tool:   spec.Name,
				Reason: "Level 5 SDR mode — use /locate-advanced",
			})
			continue
		}
		if requested != nil {
			found := false
			for _, r := range requested {
				if r == spec.Name {
					found = true
					break
				}
			}
			if !found {
				skipped = append(skipped, LocateSkipped{Tool: spec.Name, Reason: "not in --tools list"})
				continue
			}
		}
		_, err := lookPathLocate(spec.Name)
		if err != nil {
			found := false
			for _, alt := range spec.AltPaths {
				if _, e := os.Stat(alt); e == nil {
					found = true
					break
				}
			}
			if !found {
				skipped = append(skipped, LocateSkipped{
					Tool:        spec.Name,
					Reason:      "not installed",
					InstallHint: spec.InstallHint,
				})
				continue
			}
		}
		available = append(available, spec)
	}
	return available, skipped, nil
}

func runLocateToolExhaustive(spec LocateToolSpec, target string, ctx *LocateContext, progress func(LocateStatus)) (string, error) {
	var output string
	var err error

	if spec.UseShell {
		shellCmd := spec.ShellCmd(target, ctx)
		if shellCmd == "" {
			return "", fmt.Errorf("not applicable")
		}
		output, err = runShell(spec.Timeout, shellCmd)
	} else {
		args := spec.BuildArgs(target, ctx)
		if len(args) == 0 {
			return "", fmt.Errorf("not applicable")
		}
		output, err = run(spec.Timeout, spec.Name, args...)
	}

	if strings.TrimSpace(output) != "" {
		return output, err
	}

	for i, fallbackFn := range spec.FallbackArgs {
		progress(LocateStatus{Tool: spec.Name, Kind: LocateRetry,
			Reason: fmt.Sprintf("fallback %d/%d", i+1, len(spec.FallbackArgs))})
		fbArgs := fallbackFn(target, ctx)
		if len(fbArgs) == 0 {
			continue
		}
		fbOut, fbErr := run(spec.Timeout, spec.Name, fbArgs...)
		if strings.TrimSpace(fbOut) != "" {
			return fmt.Sprintf("[fallback-%d]\n%s", i+1, fbOut), fbErr
		}
	}

	return output, err
}

func addLocateResult(result *LocateResult, spec LocateToolSpec, output string, err error, took time.Duration) {
	tr := LocateToolResult{Tool: spec.Name, Took: took}
	if output != "" {
		tr.Output = sanitizeLocate(output, 50000)
		tr.Partial = err != nil
		if tr.Partial {
			tr.Error = err.Error()
		}
		result.Tools = append(result.Tools, spec.Name)
	} else if err != nil {
		tr.Error = err.Error()
		result.Failed = append(result.Failed, tr)
	}
	result.Results = append(result.Results, tr)
}

func saveLocateSession(ctx *LocateContext) {
	if ctx.SessionDir == "" {
		return
	}
	session := LocateSession{
		Target:      ctx.Target,
		TargetType:  ctx.TargetType,
		StartedAt:   ctx.StartedAt,
		Coordinates: ctx.Coordinates,
		City:        ctx.City,
		Country:     ctx.Country,
	}
	data, _ := json.MarshalIndent(session, "", "  ")
	os.WriteFile(ctx.SessionDir+"/session.json", data, 0600)
}

// ─── Main Engine ──────────────────────────────────────────────────────────────

// RunLocate executes the geolocation pipeline.
func RunLocate(target string, advanced bool, requested []string, progress func(LocateStatus)) LocateResult {
	result := LocateResult{Target: target}

	ctx := &LocateContext{
		Target:     target,
		TargetType: detectLocateTargetType(target),
		Advanced:   advanced,
		StartedAt:  time.Now(),
	}

	safe := strings.NewReplacer(".", "_", "+", "", " ", "_", "/", "_", "@", "_at_").Replace(target)
	ctx.SessionDir = fmt.Sprintf("/tmp/cybermind_locate_%s", safe)
	os.MkdirAll(ctx.SessionDir, 0700)

	// Quick free API lookup first
	if ctx.TargetType == "ip" || ctx.TargetType == "domain" {
		ip := target
		if ctx.TargetType == "domain" {
			addrs, err := net.LookupHost(target)
			if err == nil && len(addrs) > 0 {
				ip = addrs[0]
				ctx.IPAddresses = addrs
			}
		}
		if apiResult := ipinfoLookup(ip); apiResult != "" {
			result.Results = append(result.Results, LocateToolResult{
				Tool:   "ipinfo-api",
				Output: apiResult,
				Took:   0,
			})
			result.Tools = append(result.Tools, "ipinfo-api")
			updateLocateContext("ipinfo", apiResult, ctx)
		}
	}

	available, skipped, err := detectLocateTools(requested, advanced)
	if err != nil {
		result.Skipped = append(result.Skipped, LocateSkipped{Tool: "all", Reason: err.Error()})
		return result
	}
	result.Skipped = skipped

	for _, s := range skipped {
		progress(LocateStatus{Tool: s.Tool, Kind: LocateKindSkipped, Reason: s.Reason})
	}

	maxLevel := 4
	if advanced {
		maxLevel = 5
	}

	for level := 1; level <= maxLevel; level++ {
		for _, spec := range available {
			if spec.Level != level {
				continue
			}
			// Filter by target type
			if len(spec.TargetTypes) > 0 {
				match := false
				for _, tt := range spec.TargetTypes {
					if tt == "all" || tt == ctx.TargetType {
						match = true
						break
					}
				}
				if !match {
					result.Skipped = append(result.Skipped, LocateSkipped{
						Tool:   spec.Name,
						Reason: fmt.Sprintf("not for %s targets", ctx.TargetType),
					})
					progress(LocateStatus{Tool: spec.Name, Kind: LocateKindSkipped,
						Reason: fmt.Sprintf("not for %s", ctx.TargetType)})
					continue
				}
			}

			progress(LocateStatus{Tool: spec.Name, Kind: LocateRunning})
			start := time.Now()
			output, runErr := runLocateToolExhaustive(spec, target, ctx, progress)
			took := time.Since(start)

			addLocateResult(&result, spec, output, runErr, took)

			last := result.Results[len(result.Results)-1]
			var kind LocateStatusKind
			switch {
			case last.Partial:
				kind = LocatePartial
			case last.Error != "" && last.Output == "":
				kind = LocateFailed
			default:
				kind = LocateDone
			}
			progress(LocateStatus{Tool: spec.Name, Kind: kind, Took: took, Reason: last.Error})

			if output != "" {
				updateLocateContext(spec.Name, output, ctx)
				saveLocateSession(ctx)
			}
		}
	}

	result.Context = ctx
	return result
}

// LocateToolNames returns all tool names.
func LocateToolNames() []string {
	names := make([]string, len(locateRegistry))
	for i, s := range locateRegistry {
		names[i] = s.Name
	}
	return names
}

// GetLocateCombinedOutput returns all tool outputs as one string.
func GetLocateCombinedOutput(r LocateResult) string {
	var b strings.Builder
	for _, tr := range r.Results {
		if tr.Output != "" {
			b.WriteString(fmt.Sprintf("=== %s ===\n%s\n\n", strings.ToUpper(tr.Tool), tr.Output))
		}
	}
	return b.String()
}
