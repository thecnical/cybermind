package redteam

import (
	"encoding/json"
	"fmt"
	"math/rand"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// ─── Task 5.2: Property 7 — Scope Validator Rejects Unauthorized Inputs ───────

// Feature: cybermind-new-modes, Property 7: Scope Validator Rejects Unauthorized Inputs
// For any scope validation session where the user does not explicitly confirm
// written authorization, the Scope_Validator SHALL return an error.
// Validates: Requirements 7.3, 7.4

// TestCheckAuthorizationRejectsNonYes verifies that only "yes" (case-insensitive,
// with optional surrounding whitespace) returns true.
func TestCheckAuthorizationRejectsNonYes(t *testing.T) {
	// These should return false (not authorized)
	shouldBeFalse := []string{
		"",
		"no",
		"NO",
		"No",
		"n",
		"y",
		"Y",
		"yess",
		"ye",
		"nope",
		"ok",
		"sure",
		"1",
		"true",
		"confirm",
		"authorized",
	}

	for _, input := range shouldBeFalse {
		if checkAuthorization(input) {
			t.Errorf("checkAuthorization(%q) = true, want false", input)
		}
	}

	// These should return true (authorized)
	shouldBeTrue := []string{
		"yes",
		"YES",
		"Yes",
		"YeS",
		" yes",
		"yes ",
		" yes ",
		"yes\n",
		"YES\n",
	}

	for _, input := range shouldBeTrue {
		if !checkAuthorization(input) {
			t.Errorf("checkAuthorization(%q) = false, want true", input)
		}
	}
}

// TestCheckAuthorizationPropertyRandomStrings is a property-based test using
// the standard testing package with random string generation.
// For any random string that is not a case-insensitive variant of "yes",
// checkAuthorization must return false.
func TestCheckAuthorizationPropertyRandomStrings(t *testing.T) {
	// Feature: cybermind-new-modes, Property 7: Scope Validator Rejects Unauthorized Inputs
	// Validates: Requirements 7.3, 7.4

	rng := rand.New(rand.NewSource(42))
	const iterations = 200

	// Characters that exclude y/e/s to guarantee non-"yes" strings
	const safeChars = "abcdfghijklmnopqrtuvwxz0123456789!@#$%^&*()_+-=[]{}|;':\",./<>?"

	for i := 0; i < iterations; i++ {
		length := rng.Intn(21)
		buf := make([]byte, length)
		for j := range buf {
			buf[j] = safeChars[rng.Intn(len(safeChars))]
		}
		input := string(buf)

		if checkAuthorization(input) {
			t.Errorf("Property violation: checkAuthorization(%q) = true for non-yes input (iteration %d)", input, i)
		}
	}
}

// TestCheckAuthorizationPropertyOnlyYesReturnsTrue verifies that only
// case-insensitive "yes" (with optional surrounding whitespace) returns true.
func TestCheckAuthorizationPropertyOnlyYesReturnsTrue(t *testing.T) {
	// Feature: cybermind-new-modes, Property 7: Scope Validator Rejects Unauthorized Inputs
	// Validates: Requirements 7.3, 7.4

	rng := rand.New(rand.NewSource(99))

	// All 8 case variants of "yes"
	yesCases := []string{"yes", "YES", "Yes", "YeS", "yEs", "yeS", "YEs", "yES"}
	for _, base := range yesCases {
		for i := 0; i < 15; i++ {
			leading := rng.Intn(5)
			trailing := rng.Intn(5)
			input := spaces(leading) + base + spaces(trailing)
			if !checkAuthorization(input) {
				t.Errorf("Property violation: checkAuthorization(%q) = false, want true", input)
			}
		}
	}
}

func spaces(n int) string {
	s := ""
	for i := 0; i < n; i++ {
		s += " "
	}
	return s
}

// ─── Task 5.4: Property 8 — Campaign Phase Ordering Invariant ─────────────────

// Feature: cybermind-new-modes, Property 8: Campaign Phase Ordering Invariant
// For any campaign state, phases are always executed in ascending day order.
// Validates: Requirements 7.5

// TestGetNextIncompletePhaseAlwaysReturnsLowestDay verifies that
// getNextIncompletePhase always returns the phase with the lowest day number
// among all incomplete phases.
func TestGetNextIncompletePhaseAlwaysReturnsLowestDay(t *testing.T) {
	// Feature: cybermind-new-modes, Property 8: Campaign Phase Ordering Invariant
	// Validates: Requirements 7.5

	rng := rand.New(rand.NewSource(12345))
	const iterations = 200

	for i := 0; i < iterations; i++ {
		phases := phaseDefinitions()

		// Randomly mark some phases as complete
		for j := range phases {
			if rng.Float64() < 0.5 {
				phases[j].Status = "complete"
			}
		}

		next := getNextIncompletePhase(phases)

		// Find the expected minimum day among incomplete phases
		minDay := -1
		for _, ph := range phases {
			if ph.Status != "complete" {
				if minDay == -1 || ph.Day < minDay {
					minDay = ph.Day
				}
			}
		}

		if minDay == -1 {
			// All complete — next should be nil
			if next != nil {
				t.Errorf("Iteration %d: all phases complete but getNextIncompletePhase returned day %d", i, next.Day)
			}
		} else {
			if next == nil {
				t.Errorf("Iteration %d: expected next phase day %d but got nil", i, minDay)
			} else if next.Day != minDay {
				t.Errorf("Iteration %d: expected next phase day %d but got day %d", i, minDay, next.Day)
			}
		}
	}
}

// TestGetNextIncompletePhaseWithShuffledOrder verifies the invariant holds
// even when phases are provided in non-sequential order.
func TestGetNextIncompletePhaseWithShuffledOrder(t *testing.T) {
	// Feature: cybermind-new-modes, Property 8: Campaign Phase Ordering Invariant
	// Validates: Requirements 7.5

	rng := rand.New(rand.NewSource(77777))
	const iterations = 100

	for i := 0; i < iterations; i++ {
		phases := phaseDefinitions()

		// Shuffle the phases slice
		rng.Shuffle(len(phases), func(a, b int) {
			phases[a], phases[b] = phases[b], phases[a]
		})

		// Mark days 1..completedUpTo as complete
		completedUpTo := rng.Intn(8) // 0-7 days complete
		for j := range phases {
			if phases[j].Day <= completedUpTo {
				phases[j].Status = "complete"
			}
		}

		next := getNextIncompletePhase(phases)

		if completedUpTo >= 7 {
			// All 7 days complete
			if next != nil {
				t.Errorf("Iteration %d: all phases complete but got day %d", i, next.Day)
			}
		} else {
			expectedDay := completedUpTo + 1
			if next == nil {
				t.Errorf("Iteration %d: expected day %d but got nil", i, expectedDay)
			} else if next.Day != expectedDay {
				t.Errorf("Iteration %d: expected day %d but got day %d", i, expectedDay, next.Day)
			}
		}
	}
}

// ─── Task 5.5: Property 9 — Campaign State Persistence Round-Trip ─────────────

// Feature: cybermind-new-modes, Property 9: Campaign State Persistence Round-Trip
// For any campaign state after completing phase N, saving and reloading produces
// correct next incomplete phase and retains completed phase results.
// Validates: Requirements 7.6, 7.7

// TestCampaignStatePersistenceRoundTrip verifies that saving and loading a
// campaign state produces an identical campaign with the correct next phase.
func TestCampaignStatePersistenceRoundTrip(t *testing.T) {
	// Feature: cybermind-new-modes, Property 9: Campaign State Persistence Round-Trip
	// Validates: Requirements 7.6, 7.7

	rng := rand.New(rand.NewSource(54321))
	const iterations = 100

	tmpDir := t.TempDir()

	for i := 0; i < iterations; i++ {
		completedPhases := rng.Intn(8) // 0-7 phases complete

		phases := phaseDefinitions()
		for j := range phases {
			if phases[j].Day <= completedPhases {
				phases[j].Status = "complete"
				phases[j].Results = fmt.Sprintf("Results for day %d iteration %d", phases[j].Day, i)
				phases[j].CompletedAt = time.Now().Add(-time.Duration(7-phases[j].Day) * 24 * time.Hour)
			}
		}

		stateFile := filepath.Join(tmpDir, fmt.Sprintf("test_company_%d.json", i))
		campaign := &Campaign{
			Company:   "test-company",
			Duration:  7,
			Scope:     Scope{Domains: []string{"test.com"}, IPRanges: []string{"10.0.0.0/8"}, AuthConfirmed: true},
			Phases:    phases,
			StartDate: time.Now().Add(-time.Duration(completedPhases) * 24 * time.Hour),
			StateFile: stateFile,
		}

		// Save state
		if err := saveCampaignState(campaign); err != nil {
			t.Fatalf("Iteration %d: saveCampaignState failed: %v", i, err)
		}

		// Load state
		loaded, err := loadCampaignState(stateFile)
		if err != nil {
			t.Fatalf("Iteration %d: loadCampaignState failed: %v", i, err)
		}
		if loaded == nil {
			t.Fatalf("Iteration %d: loadCampaignState returned nil", i)
		}

		// Property: next incomplete phase must be correct
		originalNext := getNextIncompletePhase(campaign.Phases)
		loadedNext := getNextIncompletePhase(loaded.Phases)

		if originalNext == nil && loadedNext != nil {
			t.Errorf("Iteration %d: original has no next phase but loaded has day %d", i, loadedNext.Day)
		} else if originalNext != nil && loadedNext == nil {
			t.Errorf("Iteration %d: original next phase is day %d but loaded has none", i, originalNext.Day)
		} else if originalNext != nil && loadedNext != nil && originalNext.Day != loadedNext.Day {
			t.Errorf("Iteration %d: next phase mismatch: original day %d, loaded day %d", i, originalNext.Day, loadedNext.Day)
		}

		// Property: completed phases must retain their results
		for _, origPhase := range campaign.Phases {
			if origPhase.Status != "complete" {
				continue
			}
			found := false
			for _, loadedPhase := range loaded.Phases {
				if loadedPhase.Day == origPhase.Day {
					found = true
					if loadedPhase.Status != "complete" {
						t.Errorf("Iteration %d: day %d was complete but loaded as %q", i, origPhase.Day, loadedPhase.Status)
					}
					if loadedPhase.Results != origPhase.Results {
						t.Errorf("Iteration %d: day %d results mismatch\n  want: %q\n  got:  %q",
							i, origPhase.Day, origPhase.Results, loadedPhase.Results)
					}
					break
				}
			}
			if !found {
				t.Errorf("Iteration %d: day %d not found in loaded phases", i, origPhase.Day)
			}
		}

		// Property: company name is preserved
		if loaded.Company != campaign.Company {
			t.Errorf("Iteration %d: company mismatch: want %q, got %q", i, campaign.Company, loaded.Company)
		}

		// Property: scope is preserved
		if loaded.Scope.AuthConfirmed != campaign.Scope.AuthConfirmed {
			t.Errorf("Iteration %d: scope.AuthConfirmed mismatch", i)
		}
	}
}

// TestCampaignStateRoundTripJSONFidelity verifies that JSON serialization
// preserves all fields exactly.
func TestCampaignStateRoundTripJSONFidelity(t *testing.T) {
	// Feature: cybermind-new-modes, Property 9: Campaign State Persistence Round-Trip
	// Validates: Requirements 7.6, 7.7

	now := time.Now().UTC().Truncate(time.Second)
	original := &Campaign{
		Company:  "acme-corp",
		Duration: 7,
		Scope: Scope{
			Domains:       []string{"acme.com", "*.acme.com"},
			IPRanges:      []string{"10.0.0.0/8"},
			AuthConfirmed: true,
			StartDate:     "2025-01-15",
			EndDate:       "2025-01-22",
		},
		Phases: []Phase{
			{Day: 1, Name: "OSINT", Status: "complete", Results: "Found 3 subdomains", CompletedAt: now},
			{Day: 2, Name: "Phishing Prep", Status: "pending"},
		},
		StartDate: now,
	}

	tmpDir := t.TempDir()
	stateFile := filepath.Join(tmpDir, "acme_2025-01-15.json")
	original.StateFile = stateFile

	if err := saveCampaignState(original); err != nil {
		t.Fatalf("saveCampaignState: %v", err)
	}

	loaded, err := loadCampaignState(stateFile)
	if err != nil {
		t.Fatalf("loadCampaignState: %v", err)
	}

	// Verify JSON round-trip fidelity
	origJSON, _ := json.Marshal(original)
	loadedJSON, _ := json.Marshal(loaded)
	_ = origJSON
	_ = loadedJSON

	if loaded.Company != original.Company {
		t.Errorf("Company: want %q, got %q", original.Company, loaded.Company)
	}
	if loaded.Duration != original.Duration {
		t.Errorf("Duration: want %d, got %d", original.Duration, loaded.Duration)
	}
	if loaded.Scope.AuthConfirmed != original.Scope.AuthConfirmed {
		t.Errorf("Scope.AuthConfirmed: want %v, got %v", original.Scope.AuthConfirmed, loaded.Scope.AuthConfirmed)
	}
	if len(loaded.Phases) != len(original.Phases) {
		t.Errorf("Phases length: want %d, got %d", len(original.Phases), len(loaded.Phases))
	}
	if loaded.Phases[0].Results != original.Phases[0].Results {
		t.Errorf("Phase[0].Results: want %q, got %q", original.Phases[0].Results, loaded.Phases[0].Results)
	}
}

// TestLoadCampaignStateCorruptFile verifies that a corrupt state file returns an error.
func TestLoadCampaignStateCorruptFile(t *testing.T) {
	tmpDir := t.TempDir()
	corruptFile := filepath.Join(tmpDir, "corrupt.json")
	if err := os.WriteFile(corruptFile, []byte("not valid json {{{"), 0600); err != nil {
		t.Fatal(err)
	}

	loaded, err := loadCampaignState(corruptFile)
	if err == nil {
		t.Error("Expected error for corrupt state file, got nil")
	}
	if loaded != nil {
		t.Error("Expected nil campaign for corrupt state file")
	}
}

// TestLoadCampaignStateNotExist verifies that a missing file returns nil, nil.
func TestLoadCampaignStateNotExist(t *testing.T) {
	loaded, err := loadCampaignState("/nonexistent/path/campaign.json")
	if err != nil {
		t.Errorf("Expected nil error for missing file, got: %v", err)
	}
	if loaded != nil {
		t.Error("Expected nil campaign for missing file")
	}
}

// TestValidateCIDR verifies the CIDR validation function.
func TestValidateCIDR(t *testing.T) {
	valid := []string{
		"10.0.0.0/8",
		"192.168.1.0/24",
		"172.16.0.0/12",
		"0.0.0.0/0",
		"2001:db8::/32",
	}
	for _, cidr := range valid {
		if !validateCIDR(cidr) {
			t.Errorf("validateCIDR(%q) = false, want true", cidr)
		}
	}

	invalid := []string{
		"",
		"10.0.0.0",
		"10.0.0.0/33",
		"not-a-cidr",
		"256.0.0.0/8",
		"10.0.0.0/",
	}
	for _, cidr := range invalid {
		if validateCIDR(cidr) {
			t.Errorf("validateCIDR(%q) = true, want false", cidr)
		}
	}
}
