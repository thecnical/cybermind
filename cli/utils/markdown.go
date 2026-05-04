package utils

import (
	"regexp"
	"strings"
)

var (
	boldRe   = regexp.MustCompile(`\*\*(.+?)\*\*`)
	italicRe = regexp.MustCompile(`\*(.+?)\*`)
	codeRe   = regexp.MustCompile("`(.+?)`")
)

// StripMarkdown converts AI markdown to clean terminal text.
// Headings → UPPERCASED (no extra blank line — avoids double-spacing)
// **bold** → text (inline markers stripped)
// `code` → text
// ```fenced blocks``` → 4-space indented lines
// - item / * item → "  • item"
// Numbered lists preserved as-is
// Consecutive blank lines collapsed to single blank line
func StripMarkdown(s string) string {
	lines := strings.Split(s, "\n")
	var out []string
	inFence := false

	for _, line := range lines {
		if strings.HasPrefix(line, "```") {
			inFence = !inFence
			// Don't add blank line on fence open — avoids double spacing
			continue
		}
		if inFence {
			out = append(out, "    "+line)
			continue
		}
		switch {
		case strings.HasPrefix(line, "### "):
			out = append(out, "  "+strings.ToUpper(line[4:]))
		case strings.HasPrefix(line, "## "):
			out = append(out, strings.ToUpper(line[3:]))
		case strings.HasPrefix(line, "# "):
			out = append(out, strings.ToUpper(line[2:]))
		case strings.HasPrefix(line, "- ") || strings.HasPrefix(line, "* "):
			out = append(out, "  • "+stripInline(line[2:]))
		default:
			out = append(out, stripInline(line))
		}
	}

	// Collapse consecutive blank lines into a single blank line
	var collapsed []string
	prevBlank := false
	for _, l := range out {
		isBlank := strings.TrimSpace(l) == ""
		if isBlank && prevBlank {
			continue // skip duplicate blank
		}
		collapsed = append(collapsed, l)
		prevBlank = isBlank
	}

	// Trim leading/trailing blank lines
	for len(collapsed) > 0 && strings.TrimSpace(collapsed[0]) == "" {
		collapsed = collapsed[1:]
	}
	for len(collapsed) > 0 && strings.TrimSpace(collapsed[len(collapsed)-1]) == "" {
		collapsed = collapsed[:len(collapsed)-1]
	}

	return strings.Join(collapsed, "\n")
}

// stripInline removes inline markdown markers: **bold**, *italic*, `code`
func stripInline(s string) string {
	s = boldRe.ReplaceAllString(s, "$1")
	s = italicRe.ReplaceAllString(s, "$1")
	s = codeRe.ReplaceAllString(s, "$1")
	return s
}
