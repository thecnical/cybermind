# Changelog

All notable changes to CyberMind are documented here.

## [2.0.0] - 2026-04-01

### Added
- Full Kali Linux command mode: `scan`, `recon`, `exploit`, `payload`, `tool`
- 5 new backend routes: `/scan`, `/recon`, `/exploit`, `/tools`
- 9 AI providers: Groq, Cerebras, ai.cc, SambaNova, Mistral, NVIDIA, OpenRouter, HuggingFace, Bytez
- 25+ AI models with parallel execution and auto-fallback
- Massively upgraded system prompt with 100+ Kali Linux tools
- Identity override — always responds as CyberMind
- Production-ready project structure

## [1.0.0] - 2026-03-15

### Added
- Initial Go CLI with Bubble Tea interactive UI
- Node.js + Express backend
- Multi-provider AI router with fallback
- API key rotation (round-robin)
- Rate limiting (20 req/min per IP)
- Local chat history (~/.cybermind/history.json)
- Phase 1–8 implementation
