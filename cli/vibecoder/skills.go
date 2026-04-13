package vibecoder

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"
)

// ─── Skills System ────────────────────────────────────────────────────────────
//
// Skills are Markdown files that expand into full prompts when invoked with
// /skill-name. They encode repeatable tasks as first-class commands.
//
// Locations (in priority order):
//   .kiro/skills/          — project-scoped, shared with team
//   ~/.cybermind/skills/   — user-scoped, available in every project
//
// File format:
//   ---
//   name: review
//   description: Run a structured code review
//   allowed_tools: [read_file, grep_search]
//   ---
//   <prompt body>

// SkillMeta holds the YAML frontmatter of a skill file.
type SkillMeta struct {
	Name         string   `yaml:"name"`
	Description  string   `yaml:"description"`
	AllowedTools []string `yaml:"allowed_tools"`
	// Arguments that can be passed: $ARGUMENTS placeholder in body
}

// Skill is a loaded, parsed skill ready for invocation.
type Skill struct {
	Meta         SkillMeta
	Body         string // the prompt body (after frontmatter)
	SourcePath   string // absolute path to the .md file
	Scope        string // "project" | "user"
}

// SkillRegistry holds all loaded skills indexed by name.
type SkillRegistry struct {
	skills map[string]*Skill
}

// NewSkillRegistry creates an empty registry.
func NewSkillRegistry() *SkillRegistry {
	return &SkillRegistry{skills: make(map[string]*Skill)}
}

// Load scans project and user skill directories and loads all .md files.
// Project skills override user skills with the same name.
func (r *SkillRegistry) Load(workspaceRoot string) error {
	// 1. Load user-scoped skills first (lower priority)
	home, err := os.UserHomeDir()
	if err == nil {
		userDir := filepath.Join(home, ".cybermind", "skills")
		_ = r.loadDir(userDir, "user")
	}

	// 2. Load project-scoped skills (higher priority — overrides user)
	projectDir := filepath.Join(workspaceRoot, ".kiro", "skills")
	_ = r.loadDir(projectDir, "project")

	return nil
}

// loadDir loads all .md files from a directory as skills.
func (r *SkillRegistry) loadDir(dir, scope string) error {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil // directory doesn't exist — not an error
	}
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".md") {
			continue
		}
		path := filepath.Join(dir, entry.Name())
		skill, err := loadSkillFile(path, scope)
		if err != nil {
			continue // skip malformed files
		}
		r.skills[skill.Meta.Name] = skill
	}
	return nil
}

// Get returns a skill by name (the /skill-name without the slash).
func (r *SkillRegistry) Get(name string) (*Skill, bool) {
	s, ok := r.skills[name]
	return s, ok
}

// All returns all loaded skills sorted by name.
func (r *SkillRegistry) All() []*Skill {
	out := make([]*Skill, 0, len(r.skills))
	for _, s := range r.skills {
		out = append(out, s)
	}
	return out
}

// Names returns all skill names for slash menu completion.
func (r *SkillRegistry) Names() []string {
	names := make([]string, 0, len(r.skills))
	for name := range r.skills {
		names = append(names, "/"+name)
	}
	return names
}

// Expand returns the full prompt for a skill invocation.
// arguments is the text after the skill name (e.g. "/review src/main.go" → "src/main.go").
func (r *SkillRegistry) Expand(name, arguments string) (string, error) {
	skill, ok := r.skills[name]
	if !ok {
		return "", fmt.Errorf("skill %q not found", name)
	}
	body := skill.Body
	// Replace $ARGUMENTS placeholder
	body = strings.ReplaceAll(body, "$ARGUMENTS", arguments)
	body = strings.ReplaceAll(body, "${ARGUMENTS}", arguments)
	return body, nil
}

// ─── Skill file parser ────────────────────────────────────────────────────────

// loadSkillFile parses a skill .md file with optional YAML frontmatter.
func loadSkillFile(path, scope string) (*Skill, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	content := string(data)

	skill := &Skill{
		SourcePath: path,
		Scope:      scope,
	}

	// Parse YAML frontmatter if present (between --- delimiters)
	if strings.HasPrefix(content, "---") {
		parts := strings.SplitN(content, "---", 3)
		if len(parts) >= 3 {
			// parts[0] = "" (before first ---), parts[1] = frontmatter, parts[2] = body
			if err := yaml.Unmarshal([]byte(parts[1]), &skill.Meta); err != nil {
				return nil, fmt.Errorf("skill %s: invalid frontmatter: %w", path, err)
			}
			skill.Body = strings.TrimSpace(parts[2])
		} else {
			skill.Body = strings.TrimSpace(content)
		}
	} else {
		skill.Body = strings.TrimSpace(content)
	}

	// Derive name from filename if not set in frontmatter
	if skill.Meta.Name == "" {
		base := filepath.Base(path)
		skill.Meta.Name = strings.TrimSuffix(base, ".md")
	}

	// Derive description from first line of body if not set
	if skill.Meta.Description == "" && skill.Body != "" {
		firstLine := strings.SplitN(skill.Body, "\n", 2)[0]
		firstLine = strings.TrimPrefix(firstLine, "#")
		skill.Meta.Description = strings.TrimSpace(firstLine)
	}

	return skill, nil
}

// ─── Built-in skills (bundled with CBM Code) ─────────────────────────────────
// These are written to ~/.cybermind/skills/ on first run if not present.

// BuiltinSkills are the default skills shipped with CBM Code.
// Inspired by Claude Code's skill system, customized for CyberMind workflows.
var BuiltinSkills = map[string]string{
	"review": `---
name: review
description: Run a structured code review on the current changes
allowed_tools: [read_file, grep_search, list_directory]
---
Review the staged or recently edited code against these criteria:

1. **Correctness** — does the logic match the intended behavior?
2. **Error handling** — are all error paths covered? No silent failures?
3. **Security** — SQL injection, XSS, input validation, secrets in code, path traversal
4. **Performance** — N+1 queries, missing indexes, unnecessary allocations, blocking calls
5. **Test coverage** — are the new code paths tested?
6. **Code style** — consistent naming, no dead code, proper comments

Target: $ARGUMENTS

Output findings grouped by severity: **Critical**, **Major**, **Minor**, **Suggestion**.
For each finding include: file:line, description, and suggested fix.
`,

	"commit": `---
name: commit
description: Generate a conventional commit message for staged changes
allowed_tools: [run_command, read_file]
---
Review the staged git changes and generate a conventional commit message.

Format: type(scope): description

Types: feat, fix, docs, style, refactor, test, chore, perf, ci, build
- Keep subject line under 72 characters
- Use imperative mood ("add" not "added")
- If changes span multiple concerns, add a body paragraph explaining WHY (not what)
- Reference issue numbers if relevant

Run: git diff --staged
Then generate the commit message.
`,

	"security": `---
name: security
description: Deep security audit — OWASP Top 10, secrets, CVEs
allowed_tools: [read_file, grep_search, list_directory, run_command]
---
Perform a comprehensive security audit of: $ARGUMENTS

Check for:
1. **OWASP Top 10** — injection, broken auth, XSS, IDOR, security misconfig, XXE, SSRF
2. **Hardcoded secrets** — API keys, passwords, tokens, private keys in code
3. **Dependency CVEs** — check package.json/go.mod/requirements.txt for known vulnerabilities
4. **Input validation** — all user inputs sanitized and validated?
5. **Authentication/Authorization** — proper session management, JWT validation, RBAC
6. **Cryptography** — weak algorithms (MD5, SHA1), improper key management
7. **Error handling** — stack traces exposed to users? Verbose error messages?
8. **File operations** — path traversal, arbitrary file read/write
9. **Network** — SSRF, open redirects, insecure HTTP

Output: severity (Critical/High/Medium/Low), file:line, description, CVE if applicable, fix.
`,

	"test": `---
name: test
description: Generate comprehensive tests for the specified file or function
allowed_tools: [read_file, write_file, run_command]
---
Generate comprehensive tests for: $ARGUMENTS

Requirements:
1. Read the target file to understand the code
2. Write unit tests covering:
   - Happy path (normal inputs)
   - Edge cases (empty, null, boundary values)
   - Error cases (invalid inputs, failures)
   - Concurrent access if applicable
3. Use the project's existing test framework (detect from existing test files)
4. Follow the project's naming conventions
5. Include table-driven tests where appropriate
6. Mock external dependencies
7. Aim for >80% coverage of the target code

Write the test file alongside the source file.
`,

	"document": `---
name: document
description: Generate documentation for a file or module
allowed_tools: [read_file, write_file, grep_search]
---
Generate comprehensive documentation for: $ARGUMENTS

Include:
1. **Overview** — what does this module/file do?
2. **Public API** — document every exported function/class/type with:
   - Purpose
   - Parameters (name, type, description)
   - Return values
   - Error conditions
   - Example usage
3. **Architecture notes** — key design decisions, patterns used
4. **Dependencies** — what does this depend on?

Use the language's standard doc format (JSDoc, GoDoc, Python docstrings, etc.).
Update the file in-place with the documentation added.
`,

	"refactor": `---
name: refactor
description: Refactor code for clarity, performance, and maintainability
allowed_tools: [read_file, edit_file, grep_search]
---
Refactor: $ARGUMENTS

Goals:
1. **Clarity** — rename unclear variables/functions, extract complex logic into named functions
2. **DRY** — identify and eliminate code duplication
3. **Single responsibility** — split functions/classes doing too many things
4. **Error handling** — improve error messages, add missing error checks
5. **Performance** — identify obvious bottlenecks (O(n²) loops, repeated DB calls)
6. **Modern patterns** — use language idioms and best practices

Rules:
- Preserve all existing behavior (no functional changes)
- Keep the same public API
- Add a comment explaining each significant change
- Run tests after refactoring to verify nothing broke
`,

	"explain": `---
name: explain
description: Explain code in plain language
allowed_tools: [read_file, grep_search]
---
Explain this code in plain language: $ARGUMENTS

Provide:
1. **What it does** — high-level purpose in 1-2 sentences
2. **How it works** — step-by-step walkthrough of the logic
3. **Key concepts** — explain any non-obvious patterns or algorithms
4. **Data flow** — how data moves through the code
5. **Dependencies** — what external things does it rely on?
6. **Gotchas** — any surprising behavior, edge cases, or known issues

Write for a developer who is new to this codebase.
`,

	"pr": `---
name: pr
description: Generate a pull request description
allowed_tools: [run_command, read_file]
---
Generate a pull request description for the current branch changes.

Steps:
1. Run: git log main..HEAD --oneline
2. Run: git diff main...HEAD --stat
3. Read any relevant changed files

PR format:
## Summary
(What does this PR do? 2-3 sentences)

## Changes
- (bullet list of key changes)

## Testing
- (how was this tested?)

## Screenshots
(if UI changes)

## Checklist
- [ ] Tests added/updated
- [ ] Documentation updated
- [ ] No breaking changes (or migration guide provided)
`,

	"debug": `---
name: debug
description: Systematically debug an error or unexpected behavior
allowed_tools: [read_file, run_command, grep_search, edit_file]
---
Debug this issue: $ARGUMENTS

Systematic approach:
1. **Reproduce** — confirm the issue exists and understand exact conditions
2. **Isolate** — narrow down which component/function is responsible
3. **Hypothesize** — form 2-3 hypotheses about root cause
4. **Test each hypothesis** — add logging/assertions to verify
5. **Fix** — implement the minimal fix that addresses root cause
6. **Verify** — confirm the fix resolves the issue without regressions
7. **Prevent** — add a test to prevent regression

Start by reading the relevant files and any error messages.
`,

	"migrate": `---
name: migrate
description: Generate a database migration
allowed_tools: [read_file, write_file, list_directory]
---
Generate a database migration for: $ARGUMENTS

Steps:
1. Read existing schema files to understand current structure
2. Generate migration file with:
   - UP migration (apply changes)
   - DOWN migration (rollback)
   - Proper naming: YYYYMMDDHHMMSS_description.sql
3. Handle:
   - Data preservation (no destructive changes without backup)
   - Index creation for new foreign keys
   - Null constraints and defaults
   - Rollback safety

Follow the project's existing migration format and naming conventions.
`,
}

// InstallBuiltinSkills writes built-in skills to ~/.cybermind/skills/ if not present.
func InstallBuiltinSkills() error {
	home, err := os.UserHomeDir()
	if err != nil {
		return err
	}
	skillsDir := filepath.Join(home, ".cybermind", "skills")
	if err := os.MkdirAll(skillsDir, 0755); err != nil {
		return err
	}
	for name, content := range BuiltinSkills {
		path := filepath.Join(skillsDir, name+".md")
		if _, err := os.Stat(path); os.IsNotExist(err) {
			if err := os.WriteFile(path, []byte(content), 0644); err != nil {
				return fmt.Errorf("install skill %s: %w", name, err)
			}
		}
	}
	return nil
}
