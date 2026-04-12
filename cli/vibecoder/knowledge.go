package vibecoder

import "strings"

// KnowledgeChunk is a single documentation chunk from the knowledge base.
type KnowledgeChunk struct {
	Library string
	Topic   string
	Content string
	Example string
}

// KnowledgeIndex holds documentation chunks for known libraries.
type KnowledgeIndex struct {
	chunks []KnowledgeChunk
}

// NewKnowledgeIndex creates a KnowledgeIndex pre-populated with built-in library docs.
func NewKnowledgeIndex() *KnowledgeIndex {
	idx := &KnowledgeIndex{}
	idx.loadBuiltins()
	return idx
}

// Search returns top-5 chunks matching the query for the given library.
func (k *KnowledgeIndex) Search(library, query string) []KnowledgeChunk {
	query = strings.ToLower(query)
	library = strings.ToLower(library)

	var results []KnowledgeChunk
	for _, chunk := range k.chunks {
		if library != "" && !strings.EqualFold(chunk.Library, library) {
			continue
		}
		if strings.Contains(strings.ToLower(chunk.Content), query) ||
			strings.Contains(strings.ToLower(chunk.Topic), query) {
			results = append(results, chunk)
			if len(results) >= 5 {
				break
			}
		}
	}
	return results
}

// loadBuiltins populates the index with stub entries for known libraries.
func (k *KnowledgeIndex) loadBuiltins() {
	libs := []string{
		"GSAP", "Framer Motion", "Three.js", "React Three Fiber", "Lenis",
		"AutoAnimate", "React Spring", "Anime.js", "Aceternity UI", "Magic UI",
		"shadcn/ui", "Origin UI", "Radix UI", "Headless UI", "DaisyUI",
		"Mantine", "Chakra UI", "Tailwind CSS v4", "UnoCSS", "Babylon.js",
		"Pixi.js", "D3.js", "React Native", "NativeWind", "Reanimated",
		"Tamagui", "Capacitor",
	}
	for _, lib := range libs {
		k.chunks = append(k.chunks, KnowledgeChunk{
			Library: lib,
			Topic:   "overview",
			Content: lib + " is a popular library. See official docs for full API reference.",
			Example: "// See " + lib + " documentation for examples",
		})
	}
}

// KnowledgeSearchTool implements the knowledge_search tool.
type KnowledgeSearchTool struct {
	index *KnowledgeIndex
}

func NewKnowledgeSearchTool(index *KnowledgeIndex) *KnowledgeSearchTool {
	return &KnowledgeSearchTool{index: index}
}
