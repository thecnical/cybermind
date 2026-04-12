package vibecoder

import "fmt"

// ApprovalPolicy describes how a permission level is handled in a given edit mode.
type ApprovalPolicy int

const (
	PolicyAllow   ApprovalPolicy = iota // execute without approval
	PolicyApprove                       // show approval gate before executing
	PolicyDeny                          // never execute
)

// PermissionMatrix maps (EditMode, PermissionLevel) → ApprovalPolicy.
// This is the 5 edit modes × 4 permission levels matrix.
var PermissionMatrix = map[EditMode]map[PermissionLevel]ApprovalPolicy{
	EditModeGuard: {
		PermRead:    PolicyApprove,
		PermWrite:   PolicyApprove,
		PermExecute: PolicyApprove,
		PermNetwork: PolicyApprove,
	},
	EditModeAutoEdit: {
		PermRead:    PolicyAllow,
		PermWrite:   PolicyAllow, // auto-apply, still shows diff in TUI
		PermExecute: PolicyApprove,
		PermNetwork: PolicyApprove,
	},
	EditModeBlueprint: {
		PermRead:    PolicyAllow,
		PermWrite:   PolicyDeny, // no writes until plan approved
		PermExecute: PolicyDeny,
		PermNetwork: PolicyAllow,
	},
	EditModeAutopilot: {
		PermRead:    PolicyAllow,
		PermWrite:   PolicyApprove, // dynamic risk assessment (simplified: approve)
		PermExecute: PolicyApprove,
		PermNetwork: PolicyAllow,
	},
	EditModeUnleashed: {
		PermRead:    PolicyAllow,
		PermWrite:   PolicyAllow,
		PermExecute: PolicyAllow,
		PermNetwork: PolicyAllow,
	},
}

// CheckPermission returns the ApprovalPolicy for the given edit mode and permission level.
// Returns PolicyDeny for unknown combinations.
func CheckPermission(mode EditMode, level PermissionLevel) ApprovalPolicy {
	if modeMap, ok := PermissionMatrix[mode]; ok {
		if policy, ok := modeMap[level]; ok {
			return policy
		}
	}
	return PolicyDeny
}

// PermissionIndicator returns a status indicator string for TUI display.
// 🟢 = all allowed, 🟡 = some require approval, 🔴 = some denied
func PermissionIndicator(mode EditMode) string {
	modeMap, ok := PermissionMatrix[mode]
	if !ok {
		return "🔴"
	}
	hasDeny := false
	hasApprove := false
	for _, policy := range modeMap {
		switch policy {
		case PolicyDeny:
			hasDeny = true
		case PolicyApprove:
			hasApprove = true
		}
	}
	if hasDeny {
		return "🔴"
	}
	if hasApprove {
		return "🟡"
	}
	return "🟢"
}

// EnforceNoExec returns an error if NoExec is set and the permission level is Execute.
func EnforceNoExec(noExec bool, level PermissionLevel) error {
	if noExec && level == PermExecute {
		return fmt.Errorf("command execution disabled (--no-exec flag)")
	}
	return nil
}
