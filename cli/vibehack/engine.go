package vibehack

import (
	"bufio"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"cybermind-cli/api"
	"cybermind-cli/storage"
	"github.com/charmbracelet/lipgloss"
)

// ─── Types ────────────────────────────────────────────────────────────────────

// VibeHackSession holds the full state of an autonomous hacking session.
type VibeHackSession struct {
	Target    string
	Steps     []VibeStep
	Findings  []VibeFinding
	StartTime time.Time
	EndTime   time.Time
}

// VibeStep represents one autonomous AI decision and its tool output.
type VibeStep struct {
	N         int
	Tool      string
	Reasoning string
	Output    string
}

// VibeFinding represents a confirmed vulnerability discovered during the session.
type VibeFinding struct {
	Severity string
	VulnType string
	Evidence string
}

// ─── SSE Event Types ──────────────────────────────────────────────────────────

// sseEvent is the raw JSON envelope for all SSE events from the backend.
// The design spec shows the "finding" event uses "type" for both the event
// discriminator and the vulnerability type. In practice the backend sends
// the vuln type as "vuln_type" to avoid the JSON key collision.
// We support both: if "type" != "finding" in a finding context, it's the vuln type.
type sseEvent struct {
	Type      string `json:"type"`      // event discriminator: start|step|finding|complete|error
	Target    string `json:"target"`    // start
	Step      int    `json:"step"`      // start, step
	Tool      string `json:"tool"`      // step
	Reasoning string `json:"reasoning"` // step
	Output    string `json:"output"`    // step
	Severity  string `json:"severity"`  // finding
	VulnType  string `json:"vuln_type"` // finding — vuln type (separate field to avoid collision)
	Evidence  string `json:"evidence"`  // finding
	Steps     int    `json:"steps"`     // complete
	Findings  int    `json:"findings"`  // complete
	Message   string `json:"message"`   // error
}

// parseSSEEvent parses a raw JSON string from an SSE "data: ..." line.
// Returns nil if the input is empty or cannot be parsed.
func parseSSEEvent(data string) *sseEvent {
	data = strings.TrimSpace(data)
	if data == "" {
		return nil
	}
	var ev sseEvent
	if err := json.Unmarshal([]byte(data), &ev); err != nil {
		return nil
	}
	return &ev
}

// ─── Transcript Builder ───────────────────────────────────────────────────────

// buildTranscript formats the full session into a human-readable string
// suitable for storage in Brain_Memory.
func buildTranscript(session *VibeHackSession) string {
	var sb strings.Builder
	elapsed := session.EndTime.Sub(session.StartTime).Round(time.Second)

	sb.WriteString(fmt.Sprintf("=== Vibe-Hack Session: %s ===\n", session.Target))
	sb.WriteString(fmt.Sprintf("Started:  %s\n", session.StartTime.UTC().Format(time.RFC3339)))
	sb.WriteString(fmt.Sprintf("Ended:    %s\n", session.EndTime.UTC().Format(time.RFC3339)))
	sb.WriteString(fmt.Sprintf("Elapsed:  %s\n", elapsed))
	sb.WriteString(fmt.Sprintf("Steps:    %d\n", len(session.Steps)))
	sb.WriteString(fmt.Sprintf("Findings: %d\n\n", len(session.Findings)))

	if len(session.Steps) > 0 {
		sb.WriteString("--- Steps ---\n")
		for _, s := range session.Steps {
			sb.WriteString(fmt.Sprintf("[Step %d] Tool: %s\n", s.N, s.Tool))
			if s.Reasoning != "" {
				sb.WriteString(fmt.Sprintf("  Reasoning: %s\n", s.Reasoning))
			}
			if s.Output != "" {
				sb.WriteString(fmt.Sprintf("  Output: %s\n", s.Output))
			}
		}
		sb.WriteString("\n")
	}

	if len(session.Findings) > 0 {
		sb.WriteString("--- Findings ---\n")
		for i, f := range session.Findings {
			sb.WriteString(fmt.Sprintf("[%d] [%s] %s\n", i+1, strings.ToUpper(f.Severity), f.VulnType))
			if f.Evidence != "" {
				sb.WriteString(fmt.Sprintf("    Evidence: %s\n", f.Evidence))
			}
		}
	}

	return sb.String()
}

// buildSummary formats the session summary for terminal display.
func buildSummary(session *VibeHackSession) string {
	elapsed := session.EndTime.Sub(session.StartTime).Round(time.Second)

	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("\n  Total steps:    %d\n", len(session.Steps)))
	sb.WriteString(fmt.Sprintf("  Elapsed time:   %s\n", elapsed))
	sb.WriteString(fmt.Sprintf("  Vulnerabilities found: %d\n", len(session.Findings)))

	if len(session.Findings) > 0 {
		for _, f := range session.Findings {
			sb.WriteString(fmt.Sprintf("    • [%s] %s\n", strings.ToUpper(f.Severity), f.VulnType))
		}
	}

	return sb.String()
}

// ─── Lipgloss Styles ──────────────────────────────────────────────────────────

var (
	cyanStyle    = lipgloss.NewStyle().Foreground(lipgloss.Color("14"))
	boldStyle    = lipgloss.NewStyle().Bold(true)
	findingStyle = lipgloss.NewStyle().Foreground(lipgloss.Color("9")).Bold(true)
	summaryStyle = lipgloss.NewStyle().Foreground(lipgloss.Color("10")).Bold(true)
)

// ─── Main Engine ──────────────────────────────────────────────────────────────

// RunVibeHack connects to the backend SSE stream and drives the terminal display.
// Blocks until the stream ends or the user interrupts (q / Ctrl+C).
func RunVibeHack(target string, apiKey string) error {
	session := VibeHackSession{
		Target:    target,
		StartTime: time.Now(),
	}

	// ── Build SSE request ────────────────────────────────────────────────────
	baseURL := api.GetBaseURL()
	streamURL := baseURL + "/api/vibe-hack/stream?target=" + url.QueryEscape(target)

	req, err := http.NewRequest("GET", streamURL, nil)
	if err != nil {
		return fmt.Errorf("failed to build request: %w", err)
	}
	req.Header.Set("Accept", "text/event-stream")
	req.Header.Set("Cache-Control", "no-cache")
	if apiKey == "" {
		apiKey = api.GetAPIKeyExported()
	}
	if apiKey != "" {
		req.Header.Set("X-API-Key", apiKey)
	}

	// ── Interrupt channels ───────────────────────────────────────────────────
	stopCh := make(chan struct{}, 1)

	// Ctrl+C / SIGTERM
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-sigCh
		select {
		case stopCh <- struct{}{}:
		default:
		}
	}()
	defer signal.Stop(sigCh)

	// 'q' key press on stdin
	go func() {
		buf := make([]byte, 1)
		for {
			n, err := os.Stdin.Read(buf)
			if err != nil || n == 0 {
				return
			}
			if buf[0] == 'q' || buf[0] == 'Q' {
				select {
				case stopCh <- struct{}{}:
				default:
				}
				return
			}
		}
	}()

	// ── Connect to SSE stream ────────────────────────────────────────────────
	sseClient := &http.Client{
		// No timeout — stream can run for many minutes
		Transport: &http.Transport{
			ResponseHeaderTimeout: 30 * time.Second,
		},
	}

	resp, err := sseClient.Do(req)
	if err != nil {
		return fmt.Errorf("failed to connect to vibe-hack stream: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("vibe-hack stream returned HTTP %d", resp.StatusCode)
	}

	fmt.Println()
	fmt.Println(boldStyle.Render("  ╔══════════════════════════════════════════════════════════╗"))
	fmt.Println(boldStyle.Render("  ║           🤖 Vibe-Hack — Autonomous AI Session           ║"))
	fmt.Println(boldStyle.Render("  ╚══════════════════════════════════════════════════════════╝"))
	fmt.Printf("  Target: %s\n", cyanStyle.Render(target))
	fmt.Println("  Press 'q' or Ctrl+C to stop")

	// ── Read SSE lines ───────────────────────────────────────────────────────
	scanner := bufio.NewScanner(resp.Body)
	scanner.Buffer(make([]byte, 64*1024), 64*1024)

	lineCh := make(chan string, 64)
	scanErrCh := make(chan error, 1)

	go func() {
		for scanner.Scan() {
			lineCh <- scanner.Text()
		}
		if err := scanner.Err(); err != nil {
			scanErrCh <- err
		}
		close(lineCh)
	}()

	done := false
	for !done {
		select {
		case <-stopCh:
			fmt.Println(cyanStyle.Render("\n  [!] Session interrupted by user."))
			done = true

		case err := <-scanErrCh:
			if err != nil {
				fmt.Printf("\n  [!] Stream error: %s\n", err.Error())
			}
			done = true

		case line, ok := <-lineCh:
			if !ok {
				// Channel closed — stream ended
				done = true
				break
			}

			// SSE lines: "data: {...}" or blank lines (keep-alive)
			if !strings.HasPrefix(line, "data: ") {
				continue
			}
			rawData := strings.TrimPrefix(line, "data: ")
			ev := parseSSEEvent(rawData)
			if ev == nil {
				continue
			}

			switch ev.Type {
			case "start":
				fmt.Printf("  %s\n", cyanStyle.Render(fmt.Sprintf("[AI] Starting autonomous session on %s", ev.Target)))

			case "step":
				step := VibeStep{
					N:         ev.Step,
					Tool:      ev.Tool,
					Reasoning: ev.Reasoning,
					Output:    ev.Output,
				}
				session.Steps = append(session.Steps, step)

				// Display in cyan lipgloss style: "[AI] Found PHP + MySQL -> trying SQLi next"
				msg := ev.Reasoning
				if msg == "" {
					msg = fmt.Sprintf("running %s", ev.Tool)
				}
				fmt.Printf("  %s\n", cyanStyle.Render(fmt.Sprintf("[AI] %s", msg)))
				if ev.Output != "" {
					// Indent tool output slightly
					lines := strings.Split(ev.Output, "\n")
					for _, l := range lines {
						if strings.TrimSpace(l) != "" {
							fmt.Printf("      %s\n", l)
						}
					}
				}

			case "finding":
				finding := VibeFinding{
					Severity: ev.Severity,
					VulnType: ev.VulnType,
					Evidence: ev.Evidence,
				}
				session.Findings = append(session.Findings, finding)

				label := fmt.Sprintf("[FINDING][%s] %s", strings.ToUpper(ev.Severity), ev.VulnType)
				fmt.Printf("  %s\n", findingStyle.Render(label))
				if ev.Evidence != "" {
					fmt.Printf("    Evidence: %s\n", ev.Evidence)
				}

			case "complete":
				fmt.Printf("\n  %s\n", summaryStyle.Render("[✓] Session complete"))
				done = true

			case "error":
				fmt.Printf("\n  %s\n", findingStyle.Render(fmt.Sprintf("[ERROR] %s", ev.Message)))
				done = true
			}
		}
	}

	// ── Finalize session ─────────────────────────────────────────────────────
	session.EndTime = time.Now()

	// Save transcript to Brain_Memory
	transcript := buildTranscript(&session)
	if err := storage.AddEntry("/vibe-hack "+target, transcript); err != nil {
		fmt.Printf("  [!] Warning: failed to save transcript to Brain_Memory: %s\n", err.Error())
	}

	// Display session summary
	fmt.Println()
	fmt.Println(boldStyle.Render("  ╔══════════════════════════════════════════════════════════╗"))
	fmt.Println(boldStyle.Render("  ║                   Session Summary                       ║"))
	fmt.Println(boldStyle.Render("  ╚══════════════════════════════════════════════════════════╝"))
	fmt.Print(buildSummary(&session))

	return nil
}
