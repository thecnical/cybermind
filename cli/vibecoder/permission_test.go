package vibecoder

// Feature: cybermind-vibe-coder, Property 21: Permission Level Enforcement
// Validates: Requirements 28.2, 28.5

import "testing"

func TestPermissionGuardModeRequiresApprovalForAll(t *testing.T) {
	levels := []PermissionLevel{PermRead, PermWrite, PermExecute, PermNetwork}
	for _, level := range levels {
		policy := CheckPermission(EditModeGuard, level)
		if policy != PolicyApprove {
			t.Errorf("Guard mode: expected PolicyApprove for level %d, got %d", level, policy)
		}
	}
}

func TestPermissionUnleashedModeAllowsAll(t *testing.T) {
	levels := []PermissionLevel{PermRead, PermWrite, PermExecute, PermNetwork}
	for _, level := range levels {
		policy := CheckPermission(EditModeUnleashed, level)
		if policy != PolicyAllow {
			t.Errorf("Unleashed mode: expected PolicyAllow for level %d, got %d", level, policy)
		}
	}
}

func TestPermissionBlueprintModeDeniesWriteAndExecute(t *testing.T) {
	if p := CheckPermission(EditModeBlueprint, PermWrite); p != PolicyDeny {
		t.Errorf("Blueprint mode: expected PolicyDeny for PermWrite, got %d", p)
	}
	if p := CheckPermission(EditModeBlueprint, PermExecute); p != PolicyDeny {
		t.Errorf("Blueprint mode: expected PolicyDeny for PermExecute, got %d", p)
	}
}

func TestPermissionAutoEditModeAllowsReadAndWrite(t *testing.T) {
	if p := CheckPermission(EditModeAutoEdit, PermRead); p != PolicyAllow {
		t.Errorf("AutoEdit mode: expected PolicyAllow for PermRead, got %d", p)
	}
	if p := CheckPermission(EditModeAutoEdit, PermWrite); p != PolicyAllow {
		t.Errorf("AutoEdit mode: expected PolicyAllow for PermWrite, got %d", p)
	}
	if p := CheckPermission(EditModeAutoEdit, PermExecute); p != PolicyApprove {
		t.Errorf("AutoEdit mode: expected PolicyApprove for PermExecute, got %d", p)
	}
}

func TestPermissionIndicatorReturnsCorrectEmoji(t *testing.T) {
	cases := []struct {
		mode     EditMode
		expected string
	}{
		{EditModeGuard, "🟡"},      // all approve → no deny, has approve
		{EditModeUnleashed, "🟢"}, // all allow → no deny, no approve
		{EditModeBlueprint, "🔴"}, // has deny
		{EditModeAutoEdit, "🟡"},  // has approve, no deny
		{EditModeAutopilot, "🟡"}, // has approve, no deny
	}
	for _, tc := range cases {
		got := PermissionIndicator(tc.mode)
		if got != tc.expected {
			t.Errorf("PermissionIndicator(%q): expected %s, got %s", tc.mode, tc.expected, got)
		}
	}
}

func TestPermissionUnknownModeReturnsDeny(t *testing.T) {
	policy := CheckPermission(EditMode("unknown"), PermRead)
	if policy != PolicyDeny {
		t.Errorf("Unknown mode: expected PolicyDeny, got %d", policy)
	}
}

func TestPermissionIndicatorUnknownModeReturnsRed(t *testing.T) {
	got := PermissionIndicator(EditMode("unknown"))
	if got != "🔴" {
		t.Errorf("PermissionIndicator(unknown): expected 🔴, got %s", got)
	}
}

func TestEnforceNoExecBlocksExecute(t *testing.T) {
	if err := EnforceNoExec(true, PermExecute); err == nil {
		t.Error("EnforceNoExec(true, PermExecute): expected error, got nil")
	}
}

func TestEnforceNoExecAllowsNonExecute(t *testing.T) {
	for _, level := range []PermissionLevel{PermRead, PermWrite, PermNetwork} {
		if err := EnforceNoExec(true, level); err != nil {
			t.Errorf("EnforceNoExec(true, %d): expected nil, got %v", level, err)
		}
	}
}

func TestEnforceNoExecDisabledAllowsAll(t *testing.T) {
	for _, level := range []PermissionLevel{PermRead, PermWrite, PermExecute, PermNetwork} {
		if err := EnforceNoExec(false, level); err != nil {
			t.Errorf("EnforceNoExec(false, %d): expected nil, got %v", level, err)
		}
	}
}
