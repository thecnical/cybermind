package vibecoder

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

// ---------------------------------------------------------------------------
// Property 3: Workspace Boundary Enforcement
// Validates: Requirements 4.3, 10.1, 10.2
// ---------------------------------------------------------------------------

func TestWorkspaceBoundaryEnforcement(t *testing.T) {
	// Create a temporary workspace root.
	root := t.TempDir()
	guard, err := NewWorkspaceGuard(root)
	if err != nil {
		t.Fatalf("NewWorkspaceGuard: %v", err)
	}

	// Create a file inside the workspace so EvalSymlinks can resolve it.
	insideFile := filepath.Join(root, "main.go")
	if err := os.WriteFile(insideFile, []byte("package main"), 0o644); err != nil {
		t.Fatalf("setup: %v", err)
	}

	// Create a directory outside the workspace for absolute-outside tests.
	outside := t.TempDir()

	tests := []struct {
		name    string
		path    string
		wantErr bool
	}{
		{
			name:    "valid relative path inside workspace",
			path:    "main.go",
			wantErr: false,
		},
		{
			name:    "valid absolute path inside workspace",
			path:    insideFile,
			wantErr: false,
		},
		{
			name:    "dotdot traversal relative",
			path:    "../traversal",
			wantErr: true,
		},
		{
			name:    "dotdot traversal nested",
			path:    "subdir/../../etc/passwd",
			wantErr: true,
		},
		{
			name:    "absolute path outside workspace",
			path:    filepath.Join(outside, "secret.txt"),
			wantErr: true,
		},
		{
			name:    "null byte in path",
			path:    "file\x00name",
			wantErr: true,
		},
		{
			name:    "workspace root itself",
			path:    root,
			wantErr: false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := guard.ValidatePath(tc.path)
			if tc.wantErr && err == nil {
				t.Errorf("expected error for path %q, got nil", tc.path)
			}
			if !tc.wantErr && err != nil {
				t.Errorf("unexpected error for path %q: %v", tc.path, err)
			}
		})
	}
}

// TestWorkspaceSymlinkEscape verifies that a symlink pointing outside the
// workspace is rejected (Unix only — Windows symlinks require elevated perms).
func TestWorkspaceSymlinkEscape(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlink creation requires elevated privileges on Windows")
	}

	root := t.TempDir()
	outside := t.TempDir()

	// Create a real file outside the workspace.
	outsideFile := filepath.Join(outside, "secret.txt")
	if err := os.WriteFile(outsideFile, []byte("secret"), 0o644); err != nil {
		t.Fatalf("setup: %v", err)
	}

	// Create a symlink inside the workspace pointing outside.
	link := filepath.Join(root, "escape_link")
	if err := os.Symlink(outsideFile, link); err != nil {
		t.Fatalf("symlink: %v", err)
	}

	guard, err := NewWorkspaceGuard(root)
	if err != nil {
		t.Fatalf("NewWorkspaceGuard: %v", err)
	}

	_, err = guard.ValidatePath(link)
	if err == nil {
		t.Error("expected error for symlink escaping workspace, got nil")
	}
}

// TestWorkspaceIsSensitive verifies the sensitive-file pattern matching.
func TestWorkspaceIsSensitive(t *testing.T) {
	guard, err := NewWorkspaceGuard(t.TempDir())
	if err != nil {
		t.Fatalf("NewWorkspaceGuard: %v", err)
	}

	sensitive := []string{
		".env",
		".env.production",
		"server.pem",
		"private.key",
		"cert.crt",
		"keystore.p12",
		"bundle.pfx",
		"id_rsa",
		"id_ed25519",
		"id_ecdsa",
		"putty.ppk",
		"credentials",
		"credentials.json",
		"aws.credentials",
		"secrets.yaml",
		"secrets.json",
		"db.secret",
	}

	for _, name := range sensitive {
		t.Run("sensitive/"+name, func(t *testing.T) {
			if !guard.IsSensitive(name) {
				t.Errorf("IsSensitive(%q) = false, want true", name)
			}
		})
	}

	notSensitive := []string{
		"main.go",
		"README.md",
		"config.yaml",
		"package.json",
	}

	for _, name := range notSensitive {
		t.Run("not_sensitive/"+name, func(t *testing.T) {
			if guard.IsSensitive(name) {
				t.Errorf("IsSensitive(%q) = true, want false", name)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Property 8: Command Blocklist Enforcement
// Validates: Requirements 6.5
// ---------------------------------------------------------------------------

func TestCommandBlocklist(t *testing.T) {
	blocked := []string{
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
		// With surrounding context — must still be blocked.
		"sudo rm -rf / --no-preserve-root",
		"  RM -RF /  ",
		"echo hello && cybermind uninstall",
		"mkfs.ext4 /dev/sdb",
	}

	for _, cmd := range blocked {
		t.Run("blocked/"+cmd, func(t *testing.T) {
			if !IsCommandBlocked(cmd) {
				t.Errorf("IsCommandBlocked(%q) = false, want true", cmd)
			}
		})
	}

	allowed := []string{
		"go build ./...",
		"git status",
		"ls -la",
		"echo hello world",
		"npm install",
		"docker ps",
		"cat README.md",
	}

	for _, cmd := range allowed {
		t.Run("allowed/"+cmd, func(t *testing.T) {
			if IsCommandBlocked(cmd) {
				t.Errorf("IsCommandBlocked(%q) = true, want false", cmd)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Property 13: Sensitive File Protection
// Feature: cybermind-vibe-coder
// Validates: Requirements 10.3
//
// SensitiveFileApprovalRequired must return true for all sensitive file patterns.
// It must return false for non-sensitive files.
// ---------------------------------------------------------------------------

func TestSensitiveFileApprovalRequired_SensitiveFiles(t *testing.T) {
	guard, err := NewWorkspaceGuard(t.TempDir())
	if err != nil {
		t.Fatalf("NewWorkspaceGuard: %v", err)
	}

	sensitive := []string{
		".env",
		".env.production",
		"server.pem",
		"private.key",
		"id_rsa",
		"credentials",
		"secrets.yaml",
		"db.secret",
	}

	for _, name := range sensitive {
		t.Run("sensitive/"+name, func(t *testing.T) {
			if !SensitiveFileApprovalRequired(guard, name) {
				t.Errorf("SensitiveFileApprovalRequired(%q) = false, want true", name)
			}
		})
	}
}

func TestSensitiveFileApprovalRequired_NonSensitiveFiles(t *testing.T) {
	guard, err := NewWorkspaceGuard(t.TempDir())
	if err != nil {
		t.Fatalf("NewWorkspaceGuard: %v", err)
	}

	notSensitive := []string{
		"main.go",
		"README.md",
		"config.yaml",
		"package.json",
		"Makefile",
	}

	for _, name := range notSensitive {
		t.Run("not_sensitive/"+name, func(t *testing.T) {
			if SensitiveFileApprovalRequired(guard, name) {
				t.Errorf("SensitiveFileApprovalRequired(%q) = true, want false", name)
			}
		})
	}
}
