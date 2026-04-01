# Contributing to CyberMind

Thank you for your interest in contributing!

## Reporting Bugs
Open an issue at github.com/thecnical/cybermind/issues with OS, versions, and steps to reproduce.

## Pull Requests
1. Fork the repo
2. Create a branch: `git checkout -b feature/your-feature`
3. Make changes, test, submit PR

## Development Setup

### Backend
```bash
cd backend && npm install && cp .env.example .env && node src/app.js
```

### CLI
```bash
cd cli && go mod tidy && go build -o cybermind && ./cybermind
```

## Adding a New AI Provider
1. Create `backend/src/services/yourprovider.js`
2. Add models to `backend/src/config/models.js`
3. Add env key to `backend/src/utils/keyRotation.js`
4. Register in `backend/src/services/aiRouter.js`
5. Add key to `.env.example`

## Code Standards
- Go: use `gofmt`, keep functions small, comment exports
- JS: use async/await, handle all errors, never log API keys

## License
Contributions are licensed under MIT.
