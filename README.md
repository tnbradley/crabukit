# 🔒 Crabukit

[![Python 3.9+](https://img.shields.io/badge/python-3.9+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Code style: black](https://img.shields.io/badge/code%20style-black-000000.svg)](https://github.com/psf/black)

> **A security scanner for OpenClaw skills.**

Crabukit analyzes OpenClaw skills for security vulnerabilities, malicious code patterns, prompt injection attempts, and supply chain risks before installation.

## 🚀 Quick Start

```bash
# Install
pip install crabukit

# Scan a skill before installing
crabukit scan ./my-skill/

# Scan an installed skill
crabukit scan /opt/homebrew/lib/node_modules/clawdbot/skills/suspicious-skill

# CI mode - fail on high severity
crabukit scan ./skill --fail-on=high

# JSON output for automation
crabukit scan ./skill --format=json
```

## ✨ Features

### 🔍 Comprehensive Detection

| Category | Detections |
|----------|------------|
| **Prompt Injection** | Direct, indirect, encoded, typoglycemia attacks |
| **Code Vulnerabilities** | `eval()`, `exec()`, shell injection, path traversal |
| **Secrets** | AWS keys, GitHub tokens, OpenAI keys, JWTs, private keys |
| **AI Malware** | Self-modifying code, LLM API abuse (PROMPTFLUX patterns) |
| **Supply Chain** | Typosquatting, homoglyphs, hidden files |
| **Tool Misuse** | Dangerous tool combinations (Confused Deputy attacks) |
| **Backdoors** | Cron jobs, SSH keys, persistent execution |

### 🛡️ Unique Protections

- **Typoglycemia Detection**: Catches scrambled-word attacks (`ignroe` → `ignore`)
- **Tool Combination Analysis**: Detects `browser + exec` download-and-execute chains
- **Confused Deputy Protection**: Prevents ReAct agent injection attacks
- **AI Malware Patterns**: Identifies PROMPTFLUX-style self-modifying code

## 📊 Example Output

```
🔒 Crabukit Security Report
━━━━━━━━━━━━━━━━━━━━━━━━━━━
Skill: malicious-skill
Files scanned: 3

  🔴 CRITICAL   13
  🟠 HIGH        5
  🟡 MEDIUM      6
  ⚪ INFO        1

Risk Level: CRITICAL
Score: 100/100

[CRITICAL] Dangerous tool combination: browser, exec
  Combination enables download-and-execute attack chains
  Fix: Remove unnecessary tools; implement confirmation

[CRITICAL] curl | bash pattern
  Downloads and executes remote code without verification
  Fix: Download to file, verify checksum, then execute

Recommendation: Do not install this skill.
```

## 🔌 Clawdex Integration

Crabukit **automatically detects and uses Clawdex** when installed:

```bash
# Install Clawdex for database-based protection
clawdhub install clawdex
```

**Defense in depth:**
- **Layer 1**: Clawdex checks 824+ known malicious skills (instant)
- **Layer 2**: Crabukit behavior analysis catches zero-days

**Example with both scanners:**
```
✓ External scanners: Clawdex

⚪ INFO
  → ✅ Clawdex: Verified safe
    Database reports 'skill-name' as BENIGN

🟡 MEDIUM
  → Destructive operation without warning
    (Crabukit behavior analysis)
```

## 🔧 Installation

### Via pip

```bash
pip install crabukit
```

### Via Homebrew (macOS/Linux)

```bash
brew tap moltatron/crabukit
brew install crabukit
```

### As OpenClaw Skill

```bash
clawdbot install crabukit
```

### Development

```bash
git clone https://github.com/troy/crabukit.git
cd crabukit
pip install -e ".[dev]"
```

## 🧪 CI/CD Integration

### GitHub Actions

```yaml
name: Security Scan
on: [push, pull_request]

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: troy/crabukit-action@v1
        with:
          skill-path: ./my-skill
          fail-on: high
```

### Pre-commit Hook

```yaml
repos:
  - repo: https://github.com/troy/crabukit
    rev: v0.2.0
    hooks:
      - id: crabukit-scan
        args: ['--fail-on=medium']
```

## 📚 Research-Based Detection

Crabukit's detection rules are based on:

- **OWASP Top 10 for LLM Applications** (LLM01-LLM10)
- **Lakera AI Q4 2025 Research** - Agent attack patterns
- **Google Threat Intelligence** - PROMPTFLUX/PROMPTSTEAL malware
- **WithSecure Research** - ReAct Confused Deputy attacks
- **arXiv:2410.01677** - Typoglycemia attacks on LLMs

See [RESEARCH_SUMMARY.md](RESEARCH_SUMMARY.md) for detailed references.

## 🎯 Use Cases

### Before Installing a Skill

```bash
# Download and scan before installing
clawdbot download some-skill --to ./temp
crabukit scan ./temp/some-skill
# Review results, then decide to install
```

### Auditing Installed Skills

```bash
# Scan all installed skills
for skill in /opt/homebrew/lib/node_modules/clawdbot/skills/*/; do
    crabukit scan "$skill" --fail-on=critical || echo "Issues in $skill"
done
```

### CI/CD Security Gate

```bash
# Block PRs with critical/high issues
crabukit scan ./my-skill --fail-on=high
# Exit code 1 if issues found
```

## 📖 Documentation

- [Detection Rules](docs/rules.md) - Full list of security checks
- [Contributing](CONTRIBUTING.md) - How to contribute
- [Security Policy](SECURITY.md) - Reporting vulnerabilities

## 🤝 Contributing

We welcome contributions! Please see [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

## 🛡️ Security

For security issues, please email security@crabukit.dev or see [SECURITY.md](SECURITY.md).

## 📜 License

MIT License - see [LICENSE](LICENSE) file.

## 🙏 Acknowledgments

- OpenClaw community for the skill ecosystem
- OWASP GenAI Security Project
- Researchers at Lakera AI, WithSecure, and Google Threat Intelligence

---

<p align="center">
  <sub>Built with 🦀 by <a href="https://github.com/tnbradley">@tnbradley</a></sub>
</p>
