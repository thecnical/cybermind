// Package brain — Auth-aware scanning context.
// Stores session credentials and propagates them to all downstream tools.
// Tools that support auth: httpx, katana, nuclei, dalfox, ffuf, sqlmap, gau, waybackurls.
package brain

import (
	"fmt"
	"os"
	"strings"
)

// AuthContext holds authentication credentials for authenticated scanning.
// Set once via --cookie / --bearer / --auth-header flags, propagated to all tools.
type AuthContext struct {
	// Cookie string: "session=abc123; csrf=xyz"
	Cookie string

	// Bearer token: "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
	Bearer string

	// Custom headers: "X-API-Key: abc123"
	CustomHeaders []string

	// Basic auth: "user:password"
	BasicAuth string

	// Auth proxy: route all traffic through this proxy (Burp, ZAP)
	AuthProxy string
}

// IsEmpty returns true if no auth credentials are set.
func (a *AuthContext) IsEmpty() bool {
	if a == nil {
		return true
	}
	return a.Cookie == "" && a.Bearer == "" && len(a.CustomHeaders) == 0 && a.BasicAuth == ""
}

// ToHTTPXFlags returns httpx flags for authenticated scanning.
func (a *AuthContext) ToHTTPXFlags() []string {
	if a.IsEmpty() {
		return nil
	}
	var flags []string
	if a.Cookie != "" {
		flags = append(flags, "-H", "Cookie: "+a.Cookie)
	}
	if a.Bearer != "" {
		flags = append(flags, "-H", "Authorization: Bearer "+a.Bearer)
	}
	for _, h := range a.CustomHeaders {
		flags = append(flags, "-H", h)
	}
	return flags
}

// ToKatanaFlags returns katana flags for authenticated scanning.
func (a *AuthContext) ToKatanaFlags() []string {
	if a.IsEmpty() {
		return nil
	}
	var flags []string
	if a.Cookie != "" {
		flags = append(flags, "-H", "Cookie: "+a.Cookie)
	}
	if a.Bearer != "" {
		flags = append(flags, "-H", "Authorization: Bearer "+a.Bearer)
	}
	for _, h := range a.CustomHeaders {
		flags = append(flags, "-H", h)
	}
	return flags
}

// ToNucleiFlags returns nuclei flags for authenticated scanning.
func (a *AuthContext) ToNucleiFlags() []string {
	if a.IsEmpty() {
		return nil
	}
	var flags []string
	if a.Cookie != "" {
		flags = append(flags, "-H", "Cookie: "+a.Cookie)
	}
	if a.Bearer != "" {
		flags = append(flags, "-H", "Authorization: Bearer "+a.Bearer)
	}
	for _, h := range a.CustomHeaders {
		flags = append(flags, "-H", h)
	}
	return flags
}

// ToDalfoxFlags returns dalfox flags for authenticated scanning.
func (a *AuthContext) ToDalfoxFlags() []string {
	if a.IsEmpty() {
		return nil
	}
	var flags []string
	if a.Cookie != "" {
		flags = append(flags, "--cookie", a.Cookie)
	}
	if a.Bearer != "" {
		flags = append(flags, "--header", "Authorization: Bearer "+a.Bearer)
	}
	for _, h := range a.CustomHeaders {
		flags = append(flags, "--header", h)
	}
	return flags
}

// ToSQLMapFlags returns sqlmap flags for authenticated scanning.
func (a *AuthContext) ToSQLMapFlags() []string {
	if a.IsEmpty() {
		return nil
	}
	var flags []string
	if a.Cookie != "" {
		flags = append(flags, "--cookie", a.Cookie)
	}
	if a.Bearer != "" {
		flags = append(flags, "-H", "Authorization: Bearer "+a.Bearer)
	}
	for _, h := range a.CustomHeaders {
		flags = append(flags, "-H", h)
	}
	if a.BasicAuth != "" {
		flags = append(flags, "--auth-type=basic", "--auth-cred="+a.BasicAuth)
	}
	return flags
}

// ToFFUFFlags returns ffuf flags for authenticated scanning.
func (a *AuthContext) ToFFUFFlags() []string {
	if a.IsEmpty() {
		return nil
	}
	var flags []string
	if a.Cookie != "" {
		flags = append(flags, "-H", "Cookie: "+a.Cookie)
	}
	if a.Bearer != "" {
		flags = append(flags, "-H", "Authorization: Bearer "+a.Bearer)
	}
	for _, h := range a.CustomHeaders {
		flags = append(flags, "-H", h)
	}
	return flags
}

// ToGAUFlags returns gau flags for authenticated scanning.
func (a *AuthContext) ToGAUFlags() []string {
	// gau doesn't support auth headers directly — set via env
	if a.IsEmpty() {
		return nil
	}
	return nil // gau uses env vars, handled by SetEnv()
}

// SetEnv sets environment variables so tools that read from env get auth context.
// Called once before running any tool pipeline.
func (a *AuthContext) SetEnv() {
	if a.IsEmpty() {
		return
	}
	if a.Cookie != "" {
		os.Setenv("CYBERMIND_AUTH_COOKIE", a.Cookie)
	}
	if a.Bearer != "" {
		os.Setenv("CYBERMIND_AUTH_BEARER", a.Bearer)
	}
	if a.BasicAuth != "" {
		os.Setenv("CYBERMIND_AUTH_BASIC", a.BasicAuth)
	}
	if len(a.CustomHeaders) > 0 {
		os.Setenv("CYBERMIND_AUTH_HEADERS", strings.Join(a.CustomHeaders, "||"))
	}
	if a.AuthProxy != "" {
		os.Setenv("CYBERMIND_AUTH_PROXY", a.AuthProxy)
		os.Setenv("HTTP_PROXY", a.AuthProxy)
		os.Setenv("HTTPS_PROXY", a.AuthProxy)
	}
}

// LoadAuthFromEnv loads auth context from environment variables.
// Used when auth was set in a parent process (e.g. /plan → /recon → /hunt chain).
func LoadAuthFromEnv() *AuthContext {
	ctx := &AuthContext{
		Cookie:    os.Getenv("CYBERMIND_AUTH_COOKIE"),
		Bearer:    os.Getenv("CYBERMIND_AUTH_BEARER"),
		BasicAuth: os.Getenv("CYBERMIND_AUTH_BASIC"),
		AuthProxy: os.Getenv("CYBERMIND_AUTH_PROXY"),
	}
	if headers := os.Getenv("CYBERMIND_AUTH_HEADERS"); headers != "" {
		ctx.CustomHeaders = strings.Split(headers, "||")
	}
	// Also check MCP-set auth (from MCP server tool calls)
	if mcpCookie := os.Getenv("CYBERMIND_MCP_COOKIE"); mcpCookie != "" && ctx.Cookie == "" {
		ctx.Cookie = mcpCookie
	}
	if mcpBearer := os.Getenv("CYBERMIND_MCP_BEARER"); mcpBearer != "" && ctx.Bearer == "" {
		ctx.Bearer = mcpBearer
	}
	if ctx.IsEmpty() {
		return nil
	}
	return ctx
}

// ParseAuthFlags parses --cookie, --bearer, --auth-header, --auth-proxy from CLI args.
// Returns AuthContext and remaining args (with auth flags stripped).
func ParseAuthFlags(args []string) (*AuthContext, []string) {
	ctx := &AuthContext{}
	var remaining []string

	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--cookie", "-c":
			if i+1 < len(args) {
				ctx.Cookie = args[i+1]
				i++
			}
		case "--bearer", "-b":
			if i+1 < len(args) {
				ctx.Bearer = args[i+1]
				i++
			}
		case "--auth-header", "-H":
			if i+1 < len(args) {
				ctx.CustomHeaders = append(ctx.CustomHeaders, args[i+1])
				i++
			}
		case "--basic-auth":
			if i+1 < len(args) {
				ctx.BasicAuth = args[i+1]
				i++
			}
		case "--auth-proxy":
			if i+1 < len(args) {
				ctx.AuthProxy = args[i+1]
				i++
			}
		default:
			remaining = append(remaining, args[i])
		}
	}

	if ctx.IsEmpty() {
		return nil, remaining
	}
	return ctx, remaining
}

// FormatAuthSummary returns a human-readable summary of auth context.
func FormatAuthSummary(ctx *AuthContext) string {
	if ctx == nil || ctx.IsEmpty() {
		return "  🔓 No auth — unauthenticated scan (70% of bugs require auth)"
	}
	var parts []string
	if ctx.Cookie != "" {
		masked := ctx.Cookie
		if len(masked) > 20 {
			masked = masked[:20] + "..."
		}
		parts = append(parts, fmt.Sprintf("Cookie: %s", masked))
	}
	if ctx.Bearer != "" {
		masked := ctx.Bearer
		if len(masked) > 20 {
			masked = masked[:20] + "..."
		}
		parts = append(parts, fmt.Sprintf("Bearer: %s", masked))
	}
	if len(ctx.CustomHeaders) > 0 {
		parts = append(parts, fmt.Sprintf("%d custom headers", len(ctx.CustomHeaders)))
	}
	if ctx.BasicAuth != "" {
		parts = append(parts, "Basic auth")
	}
	if ctx.AuthProxy != "" {
		parts = append(parts, fmt.Sprintf("Proxy: %s", ctx.AuthProxy))
	}
	return "  🔐 Auth-aware scan: " + strings.Join(parts, " | ")
}
