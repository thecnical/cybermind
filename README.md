# ⚡ CyberMind

> AI-powered cybersecurity CLI tool — created by [github.com/thecnical](https://github.com/thecnical)

---

## Tech Stack

- Go (CLI)
- Node.js + Express (Backend)
- HuggingFace / NVIDIA / Bytez / OpenRouter (AI Providers)

---

## Project Structure

```
CyberMind/
├── backend/   # Node.js + Express API
└── cli/       # Go CLI client
```

---

## Installation

### Backend

```bash
cd backend
npm install
cp .env.example .env   # fill in your API keys
node src/app.js
```

### CLI

```bash
cd cli
go build -o cybermind
./cybermind
```

---

## Usage

```bash
# Interactive chat
./cybermind

# View chat history
./cybermind history

# Clear chat history
./cybermind clear

# Help
./cybermind help
```

### Example

```bash
./cybermind
> how to scan open ports on a target
⚡ CyberMind AI → Use nmap: nmap -sV -p- <target>...
```

---

## Environment Variables

| Variable         | Description                        |
|------------------|------------------------------------|
| `HF_KEYS`        | HuggingFace API keys (comma-sep)   |
| `NVIDIA_KEYS`    | NVIDIA NIM API keys (comma-sep)    |
| `BYTEZ_KEYS`     | Bytez API keys (comma-sep)         |
| `OPENROUTER_KEYS`| OpenRouter API keys (comma-sep)    |
| `PORT`           | Server port (default: 3000)        |

---

## CLI Environment Variables

| Variable         | Description                              |
|------------------|------------------------------------------|
| `CYBERMIND_API`  | Override backend URL (default: Render)   |

For local dev:
```bash
CYBERMIND_API=http://localhost:3000/chat ./cybermind
```

---

## Deployment (Render)

1. Push repo to GitHub
2. Go to [render.com](https://render.com) → New Web Service
3. Connect repo, set root dir to `backend`
4. Build command: `npm install`
5. Start command: `npm start`
6. Add env vars in Render dashboard
7. Deploy — get your live URL

---

## Version

`v1.0.0` — Phase 8 (Deployment)
