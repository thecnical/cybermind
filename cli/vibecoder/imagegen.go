package vibecoder

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// ImageGenRequest holds parameters for image generation.
type ImageGenRequest struct {
	Description string
	Style       string // photorealistic, illustration, icon, 3D
	Width       int
	Height      int
	Format      string // PNG, SVG, WebP
}

// ImageGenResult holds the result of image generation.
type ImageGenResult struct {
	FilePath string
	URL      string
	Error    string
}

// GenerateImage generates an image using Pollinations.ai (free, no key required).
func GenerateImage(ctx context.Context, req ImageGenRequest, outputDir string) ImageGenResult {
	if req.Width == 0 {
		req.Width = 512
	}
	if req.Height == 0 {
		req.Height = 512
	}
	if req.Format == "" {
		req.Format = "PNG"
	}

	// Build Pollinations.ai URL
	prompt := url.QueryEscape(req.Description + " " + req.Style)
	imageURL := fmt.Sprintf("https://image.pollinations.ai/prompt/%s?width=%d&height=%d&nologo=true",
		prompt, req.Width, req.Height)

	// Download the image
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodGet, imageURL, nil)
	if err != nil {
		return ImageGenResult{Error: err.Error()}
	}

	client := &http.Client{Timeout: 60 * time.Second}
	resp, err := client.Do(httpReq)
	if err != nil {
		return ImageGenResult{URL: imageURL, Error: err.Error()}
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return ImageGenResult{URL: imageURL, Error: fmt.Sprintf("HTTP %d", resp.StatusCode)}
	}

	// Save to output directory
	if err := os.MkdirAll(outputDir, 0755); err != nil {
		return ImageGenResult{URL: imageURL, Error: err.Error()}
	}

	ts := time.Now().Format("20060102_150405")
	ext := strings.ToLower(req.Format)
	filename := fmt.Sprintf("generated_%s.%s", ts, ext)
	filePath := filepath.Join(outputDir, filename)

	f, err := os.Create(filePath)
	if err != nil {
		return ImageGenResult{URL: imageURL, Error: err.Error()}
	}
	defer f.Close()

	if _, err := io.Copy(f, resp.Body); err != nil {
		return ImageGenResult{URL: imageURL, Error: err.Error()}
	}

	return ImageGenResult{FilePath: filePath, URL: imageURL}
}

// GenerateImageTool implements the generate_image tool.
type GenerateImageTool struct{}

func (t *GenerateImageTool) Name() string { return "generate_image" }
func (t *GenerateImageTool) Schema() json.RawMessage {
	return rawSchema(`{"type":"object","properties":{"description":{"type":"string"},"style":{"type":"string"},"width":{"type":"integer"},"height":{"type":"integer"},"format":{"type":"string"}},"required":["description"]}`)
}
func (t *GenerateImageTool) Execute(ctx context.Context, params json.RawMessage, env *ToolEnv) (ToolResult, error) {
	var p struct {
		Description string `json:"description"`
		Style       string `json:"style"`
		Width       int    `json:"width"`
		Height      int    `json:"height"`
		Format      string `json:"format"`
	}
	if err := json.Unmarshal(params, &p); err != nil {
		return ToolResult{}, err
	}

	outputDir := filepath.Join(env.WorkspaceRoot, "assets", "generated")
	result := GenerateImage(ctx, ImageGenRequest{
		Description: p.Description,
		Style:       p.Style,
		Width:       p.Width,
		Height:      p.Height,
		Format:      p.Format,
	}, outputDir)

	if result.Error != "" {
		return ToolResult{Error: result.Error}, nil
	}
	return ToolResult{Output: fmt.Sprintf("Image generated: %s (URL: %s)", result.FilePath, result.URL)}, nil
}
