package vibecoder

import (
	"os"
	"path/filepath"
	"strings"
)

// ProjectType represents a detected project type.
type ProjectType string

const (
	ProjectTypeNode    ProjectType = "node"
	ProjectTypeGo      ProjectType = "go"
	ProjectTypePython  ProjectType = "python"
	ProjectTypeRust    ProjectType = "rust"
	ProjectTypeUnknown ProjectType = "unknown"
)

// DetectProjectTypeFromDir detects the project type from the workspace root.
func DetectProjectTypeFromDir(root string) ProjectType {
	checks := []struct {
		file string
		typ  ProjectType
	}{
		{"package.json", ProjectTypeNode},
		{"go.mod", ProjectTypeGo},
		{"requirements.txt", ProjectTypePython},
		{"pyproject.toml", ProjectTypePython},
		{"Cargo.toml", ProjectTypeRust},
	}
	for _, c := range checks {
		if _, err := os.Stat(filepath.Join(root, c.file)); err == nil {
			return c.typ
		}
	}
	return ProjectTypeUnknown
}

// DevServerCommand returns the dev server command for a project type.
func DevServerCommand(pt ProjectType) string {
	switch pt {
	case ProjectTypeNode:
		return "npm run dev"
	case ProjectTypeGo:
		return "go run ."
	case ProjectTypePython:
		return "python -m uvicorn main:app --reload"
	default:
		return ""
	}
}

// BuildCommand returns the build command for a project type.
func BuildCommand(pt ProjectType) string {
	switch pt {
	case ProjectTypeNode:
		return "npm run build"
	case ProjectTypeGo:
		return "go build ./..."
	case ProjectTypePython:
		return "python -m build"
	case ProjectTypeRust:
		return "cargo build --release"
	default:
		return ""
	}
}

// ExplainFilePrompt returns a prompt for explaining a file.
func ExplainFilePrompt(filePath, content string) string {
	ext := strings.TrimPrefix(filepath.Ext(filePath), ".")
	return "Explain this " + ext + " file in plain language:\n\n```" + ext + "\n" + content + "\n```"
}
