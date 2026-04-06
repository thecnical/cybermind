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
// Headings → UPPERCASED + blank line
// **bold** → bold
// `code` → code
// ```fenced blocks``` → 4-space indented lines
// - item / * item → "  • item"
// Numbered lists preserved as-is
func StripMarkdown(s string) string {
	lines := strings.Split(s, "\n")
	var out []string
	inFence := false

	for _, line := range lines {
		if strings.HasPrefix(line, "```") {
			inFence = !inFence
			if inFence {
				out = append(out, "")
			}
			continue
		}
		if inFence {
			out = append(out, "    "+line)
			continue
		}
		switch {
		case strings.HasPrefix(line, "### "):
			out = append(out, strings.ToUpper(line[4:]), "")
		case strings.HasPrefix(line, "## "):
			out = append(out, strings.ToUpper(line[3:]), "")
		case strings.HasPrefix(line, "# "):
			out = append(out, strings.ToUpper(line[2:]), "")
		case strings.HasPrefix(line, "- ") || strings.HasPrefix(line, "* "):
			out = append(out, "  • "+stripInline(line[2:]))
		default:
			out = append(out, stripInline(line))
		}
	}
	return strings.Join(out, "\n")
}

// stripInline removes inline markdown markers: **bold**, *italic*, `code`
func stripInline(s string) string {
	s = boldRe.ReplaceAllString(s, "$1")
	s = italicRe.ReplaceAllString(s, "$1")
	s = codeRe.ReplaceAllString(s, "$1")
	return s
}
