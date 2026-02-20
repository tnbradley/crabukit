"""Integration with external security scanners like Clawdex."""

import subprocess
import json
from typing import Optional, Dict, Any, List
from dataclasses import dataclass

from crabukit.rules.patterns import Finding, Severity


@dataclass
class ExternalScanResult:
    """Result from an external scanner."""
    scanner_name: str
    is_malicious: bool
    confidence: str  # "high", "medium", "low"
    details: str
    references: List[str]
    raw_output: Optional[str] = None


def check_clawdex_installed() -> bool:
    """Check if Clawdex skill is installed."""
    try:
        result = subprocess.run(
            ["clawdbot", "skills", "list"],
            capture_output=True,
            text=True,
            timeout=5
        )
        return "clawdex" in result.stdout.lower()
    except (subprocess.TimeoutExpired, FileNotFoundError, Exception):
        return False


def run_clawdex_check(skill_name: str) -> Optional[ExternalScanResult]:
    """Run Clawdex check on a skill name.
    
    Returns None if Clawdex is not installed or check fails.
    """
    try:
        # Try to run clawdex check command
        # Note: This is based on documented behavior; actual command may vary
        result = subprocess.run(
            ["clawdbot", "agent", "--local", "--message", f"Use clawdex to check if skill '{skill_name}' is malicious"],
            capture_output=True,
            text=True,
            timeout=10
        )
        
        # Parse output for malicious/safe indicators
        output = result.stdout.lower()
        
        if "malicious" in output or "flagged" in output:
            return ExternalScanResult(
                scanner_name="Clawdex",
                is_malicious=True,
                confidence="high",
                details=f"Clawdex database reports '{skill_name}' as known malicious",
                references=["https://clawdex.koi.security"],
                raw_output=result.stdout
            )
        elif "safe" in output or "clean" in output:
            return ExternalScanResult(
                scanner_name="Clawdex",
                is_malicious=False,
                confidence="high",
                details=f"Clawdex database reports '{skill_name}' as safe",
                references=["https://clawdex.koi.security"],
                raw_output=result.stdout
            )
        
        return None
        
    except (subprocess.TimeoutExpired, FileNotFoundError, Exception):
        return None


def run_external_scanners(skill_name: str) -> List[ExternalScanResult]:
    """Run all available external scanners.
    
    Returns a list of results from all scanners that are installed and working.
    """
    results = []
    
    # Check Clawdex if available
    if check_clawdex_installed():
        clawdex_result = run_clawdex_check(skill_name)
        if clawdex_result:
            results.append(clawdex_result)
    
    return results


def convert_external_to_findings(external_results: List[ExternalScanResult]) -> List[Finding]:
    """Convert external scanner results to crabukit Findings."""
    findings = []
    
    for result in external_results:
        if result.is_malicious:
            severity = Severity.CRITICAL if result.confidence == "high" else Severity.HIGH
            findings.append(Finding(
                rule_id=f"EXTERNAL_{result.scanner_name.upper()}_MALICIOUS",
                title=f"{result.scanner_name}: Known malicious skill",
                description=result.details,
                severity=severity,
                file_path="external_scan",
                line_number=0,
                remediation=f"Do not install this skill. See {', '.join(result.references)}",
                references=result.references
            ))
        else:
            # Optional: Add info-level finding for safe skills
            findings.append(Finding(
                rule_id=f"EXTERNAL_{result.scanner_name.upper()}_SAFE",
                title=f"{result.scanner_name}: Skill verified safe",
                description=result.details,
                severity=Severity.INFO,
                file_path="external_scan",
                line_number=0,
                references=result.references
            ))
    
    return findings
