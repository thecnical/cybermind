package vibecoder

// FileDiff represents a diff between old and new file content
type FileDiff struct {
	Path     string
	OldLines []DiffLine
	NewLines []DiffLine
	IsNew    bool
}

type DiffKind int

const (
	DiffContext DiffKind = iota
	DiffAdded
	DiffRemoved
)

type DiffLine struct {
	LineNo  int
	Content string
	Kind    DiffKind
}
