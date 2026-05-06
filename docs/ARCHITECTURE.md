# CyberMind Architecture

## System Overview

CyberMind is organized as a tool-orchestration CLI with AI-assisted planning and summarization.

1. User enters command (`/plan`, `/recon`, `/hunt`, `/abhimanyu`, `/doctor`)
2. Command router validates platform and target
3. Mode-specific registry builds execution graph
4. Tool runner executes commands with fallbacks and timeout controls
5. Findings are normalized into structured context
6. AI layer generates plan, triage, and response text

## Components

- `cli/main.go`: command routing, help, platform gating, doctor entrypoint
- `cli/recon/*`: recon registry and execution logic
- `cli/hunt/*`: vulnerability hunt registry and execution logic
- `cli/abhimanyu/*`: exploit/post-exploit registry
- `cli/omega/*`: OMEGA plan and tool install orchestration
- backend service: model routing, auth, usage controls
- VSCode extension: frontend and automation surface for coding/AppSec

## Design Principles

- Tool exhaustion over shallow scanning
- Fallback-first execution for reliability
- Linux-first for heavy offensive workflows
- Cross-platform chat for accessibility
- Clear separation of orchestration vs. provider/model logic

