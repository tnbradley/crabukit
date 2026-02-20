---
name: crabukit
description: Security scanner for OpenClaw skills. Analyzes SKILL.md and scripts for dangerous permissions, hardcoded secrets, shell injection vulnerabilities, and malicious code patterns. Use when (1) installing a skill from an untrusted source, (2) developing a skill before publishing, (3) auditing installed skills, or (4) running CI/CD security checks.
---

# 🔒 Crabukit

Security scanner for OpenClaw skills. Prevents installation of malicious or vulnerable skills by static analysis.

## Quick Start

```bash
# Scan a local skill before installing
crabukit scan ./suspicious-skill/

# Scan an installed skill
crabukit scan /opt/homebrew/lib/node_modules/clawdbot/skills/unknown-skill

# CI mode - fail on high severity or above
crabukit scan ./my-skill --fail-on=high

# List all detection rules
crabukit list-rules
```

## What It Detects

| Category | Issues |
|----------|--------|
| **Secrets** | Hardcoded API keys, private keys, passwords |
| **Code Injection** | `eval()`, `exec()`, `subprocess(shell=True)` |
| **Shell Risks** | `curl \| bash`, `rm -rf`, unquoted variables |
| **Permissions** | Dangerous tool requests without safety guidance |
| **Metadata** | Suspicious patterns in SKILL.md descriptions |

## Risk Scoring

Crabukit assigns a score (0-100) based on findings:

| Score | Level | Action |
|-------|-------|--------|
| 0 | Clean | Safe to install |
| 1-9 | Low | Minor issues |
| 10-24 | Medium | Review findings |
| 25-49 | High | Careful review required |
| 50+ | Critical | Do not install |

## Exit Codes

- `0` - Scan completed, no findings at or above `--fail-on` threshold
- `1` - Findings at or above threshold detected

## CI/CD Integration

```yaml
# .github/workflows/security.yml
- name: Scan skill
  run: |
    pip install crabukit
    crabukit scan ./my-skill --fail-on=medium
```

## Installation

```bash
# As OpenClaw skill
clawdbot install crabukit

# Or via pip
pip install crabukit
```
