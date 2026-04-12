package vibecoder

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
)

// WorkspaceGuard enforces that all file operations stay within the workspace root.
type WorkspaceGuard struct {
	root        string
	sensitiveRe []*regexp.Regexp
}

// NewWorkspaceGuard creates a WorkspaceGuard rooted at the given directory.
// The root is resolved to an absolute, symlink-free path.
func NewWorkspaceGuard(root string) (*WorkspaceGuard, error) {
	absRoot, err := filepath.Abs(root)
	if err != nil {
		return nil, fmt.Errorf("workspace guard: cannot resolve root %q: %w", root, err)
	}
	// Resolve symlinks in the root itself so comparisons are consistent.
	resolvedRoot, err := filepath.EvalSymlinks(absRoot)
	if err != nil {
		// If the root doesn't exist yet, fall back to the abs path.
		resolvedRoot = absRoot
	}

	patterns := []string{
		`(?i)^\.env$`,
		`(?i)^\.env\..*$`,
		`(?i)^.*\.pem$`,
		`(?i)^.*\.key$`,
		`(?i)^.*\.crt$`,
		`(?i)^.*\.p12$`,
		`(?i)^.*\.pfx$`,
		`(?i)^id_rsa$`,
		`(?i)^id_ed25519$`,
		`(?i)^id_ecdsa$`,
		`(?i)^.*\.ppk$`,
		`(?i)^credentials$`,
		`(?i)^credentials\..*$`,
		`(?i)^.*\.credentials$`,
		`(?i)^secrets\.yaml$`,
		`(?i)^secrets\.json$`,
		`(?i)^.*\.secret$`,
	}

	compiled := make([]*regexp.Regexp, 0, len(patterns))
	for _, p := range patterns {
		compiled = append(compiled, regexp.MustCompile(p))
	}

	return &WorkspaceGuard{
		root:        resolvedRoot,
		sensitiveRe: compiled,
	}, nil
}

// ValidatePath checks that p is inside the workspace root and returns the
// cleaned absolute path. It rejects null bytes, path traversal, and symlinks
// that escape the workspace.
func (g *WorkspaceGuard) ValidatePath(p string) (string, error) {
	// Reject null bytes immediately.
	if strings.ContainsRune(p, '\x00') {
		return "", fmt.Errorf("security: path contains null byte")
	}

	// Normalize separators and clean dot/dotdot components.
	cleaned := filepath.Clean(p)

	// Reject if any dotdot remains after cleaning (shouldn't happen after
	// Clean, but be explicit for clarity).
	if strings.Contains(cleaned, "..") {
		return "", fmt.Errorf("security: path traversal detected in %q", p)
	}

	// Resolve to absolute path. If the cleaned path is relative, join it
	// with the workspace root first.
	var absPath string
	if filepath.IsAbs(cleaned) {
		absPath = cleaned
	} else {
		absPath = filepath.Join(g.root, cleaned)
	}
	// filepath.Abs also calls Clean, ensuring a canonical form.
	absPath, err := filepath.Abs(absPath)
	if err != nil {
		return "", fmt.Errorf("security: cannot make path absolute: %w", err)
	}

	// Check containment before resolving symlinks.
	if !g.isInsideRoot(absPath) {
		return "", fmt.Errorf("security: path %q is outside workspace root %q", absPath, g.root)
	}

	// Resolve symlinks and re-check.
	resolved, err := filepath.EvalSymlinks(absPath)
	if err != nil {
		// If the path doesn't exist yet, we can't resolve symlinks; that's OK —
		// the pre-symlink check already passed.
		return absPath, nil
	}

	if !g.isInsideRoot(resolved) {
		return "", fmt.Errorf("security: symlink %q resolves to %q which is outside workspace root %q",
			absPath, resolved, g.root)
	}

	return absPath, nil
}

// isInsideRoot returns true when p is the root itself or a descendant of it.
func (g *WorkspaceGuard) isInsideRoot(p string) bool {
	sep := string(os.PathSeparator)
	if runtime.GOOS == "windows" {
		return strings.EqualFold(p, g.root) ||
			strings.EqualFold(p[:min(len(p), len(g.root)+len(sep))], g.root+sep) &&
				len(p) > len(g.root)
	}
	return p == g.root || strings.HasPrefix(p, g.root+sep)
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// IsSensitive returns true if the base name of p matches any sensitive-file pattern.
func (g *WorkspaceGuard) IsSensitive(p string) bool {
	base := filepath.Base(p)
	for _, re := range g.sensitiveRe {
		if re.MatchString(base) {
			return true
		}
	}
	return false
}

// blockedCommands is the list of dangerous command substrings.
var blockedCommands = []string{
	"rm -rf /",
	"rm -rf ~",
	"format c:",
	`del /f /s /q c:\`,
	"cybermind uninstall",
	"curl | sh",
	"wget | sh",
	"> /dev/sda",
	"dd if=",
	"mkfs.",
}

// IsCommandBlocked returns true if cmd (lowercased, trimmed) contains any
// blocked pattern.
func IsCommandBlocked(cmd string) bool {
	lower := strings.ToLower(strings.TrimSpace(cmd))
	for _, blocked := range blockedCommands {
		if strings.Contains(lower, strings.ToLower(blocked)) {
			return true
		}
	}
	return false
}

// Task 28: Sensitive file protection flow

// SensitiveFileApprovalRequired returns true if the file requires approval before
// including its content in the AI context.
func SensitiveFileApprovalRequired(guard *WorkspaceGuard, path string) bool {
	return guard.IsSensitive(path)
}
