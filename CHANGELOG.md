# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.2.0] - 2026-02-20

### Added
- Initial release of Crabukit - comprehensive OpenClaw skill security scanner
- **Prompt Injection Detection**: Direct, indirect, encoded, and typoglycemia attacks
- **Code Vulnerability Detection**: eval(), exec(), shell injection, path traversal
- **Secret Detection**: AWS keys, GitHub tokens, OpenAI keys, JWTs, private keys
- **AI Malware Detection**: PROMPTFLUX/PROMPTSTEAL-style patterns
- **Supply Chain Detection**: Typosquatting, homoglyphs, hidden files
- **Tool Combination Analysis**: Detects dangerous tool pairings (Confused Deputy)
- **Backdoor Detection**: Cron jobs, SSH keys, persistent execution
- Rich CLI output with severity colors and recommendations
- JSON output format for automation
- CI/CD integration with exit codes
- Comprehensive test suite with malicious skill fixtures

### Security
- Based on OWASP LLM Top 10
- Incorporates Lakera AI Q4 2025 research
- Implements Google Threat Intelligence malware patterns
- Protects against WithSecure's ReAct Confused Deputy attacks

[0.2.0]: https://github.com/troy/crabukit/releases/tag/v0.2.0
