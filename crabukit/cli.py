"""CLI entry point for crabukit."""

import sys
from pathlib import Path
from typing import Optional

import click

from crabukit.scanner import SkillScanner
from crabukit.formatters.cli_table import CLIFormatter


@click.group()
@click.version_option(version="0.1.0", prog_name="crabukit")
def cli():
    """🔒 Crabukit - Security scanner for OpenClaw skills.
    
    Analyze skills for security vulnerabilities, dangerous permissions,
    and malicious code patterns before installation.
    
    Examples:
        crabukit scan ./my-skill/
        crabukit scan /opt/homebrew/lib/node_modules/clawdbot/skills/unknown-skill
        crabukit scan ./skill --fail-on=high
    """
    pass


@cli.command()
@click.argument('skill_path', type=click.Path(exists=True))
@click.option('--fail-on', 
              type=click.Choice(['critical', 'high', 'medium', 'low', 'info'], case_sensitive=False),
              default=None,
              help='Exit with error code if findings at this severity or higher are found')
@click.option('--format', 
              type=click.Choice(['table', 'json', 'sarif'], case_sensitive=False),
              default='table',
              help='Output format')
def scan(skill_path: str, fail_on: Optional[str], format: str):
    """Scan a skill for security issues.
    
    SKILL_PATH is the path to the skill directory to analyze.
    """
    scanner = SkillScanner(skill_path)
    result = scanner.scan()
    
    # Output results
    if format == 'table':
        formatter = CLIFormatter()
        formatter.print_report(result)
    elif format == 'json':
        import json
        # Simple JSON output for now
        output = {
            "skill_name": result.skill_name,
            "skill_path": str(result.skill_path),
            "score": result.score,
            "risk_level": result.risk_level,
            "files_scanned": result.files_scanned,
            "findings": [
                {
                    "rule_id": f.rule_id,
                    "title": f.title,
                    "description": f.description,
                    "severity": f.severity.value,
                    "file": f.file_path,
                    "line": f.line_number,
                }
                for f in result.findings
            ]
        }
        click.echo(json.dumps(output, indent=2))
    
    # Determine exit code
    if fail_on:
        severity_order = {
            'critical': 4,
            'high': 3,
            'medium': 2,
            'low': 1,
            'info': 0,
        }
        threshold = severity_order.get(fail_on.lower(), 0)
        
        for finding in result.findings:
            finding_level = severity_order.get(finding.severity.value, -1)
            if finding_level >= threshold:
                sys.exit(1)
    
    sys.exit(0)


@cli.command()
def list_rules():
    """List all detection rules."""
    from crabukit.rules.patterns import (
        PYTHON_DANGEROUS_CALLS,
        PYTHON_SUBPROCESS_PATTERNS,
        BASH_PATTERNS,
        SECRET_PATTERNS,
    )
    
    click.echo("🔒 Crabukit Detection Rules")
    click.echo()
    
    click.echo("[Python Rules]")
    for name in PYTHON_DANGEROUS_CALLS:
        click.echo(f"  - {name}()")
    
    click.echo()
    click.echo("[Subprocess Rules]")
    for name in PYTHON_SUBPROCESS_PATTERNS:
        click.echo(f"  - {name}()")
    
    click.echo()
    click.echo("[Secret Detection]")
    for name in SECRET_PATTERNS:
        click.echo(f"  - {name}")
    
    click.echo()
    click.echo("[Bash Patterns]")
    for name in BASH_PATTERNS:
        click.echo(f"  - {name}")


def main():
    """Entry point."""
    cli()


if __name__ == '__main__':
    main()
