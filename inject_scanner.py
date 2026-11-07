"""
inject_scanner.py
-----------------
Custom prompt injection scanner for the DevSecOps pipeline.
Gate 4 of the security.yml workflow.

Scans all .py files in the repository for:
  - HARDCODED (string literal) system prompt variables
  - Common prompt injection bypass phrases

Exits with code 1 (FAIL) if any match is found.
Exits with code 0 (PASS) if the codebase is clean.
"""

import os
import sys
import re

# ── Patterns that indicate a HARDCODED system prompt (string literal only) ────
# We match SYSTEM_PROMPT = "..." or SYSTEM_PROMPT = '...' 
# but NOT SYSTEM_PROMPT = file.read() or os.environ.get(...)
SYSTEM_PROMPT_PATTERNS = [
    r'SYSTEM_PROMPT\s*=\s*["\']',       # e.g. SYSTEM_PROMPT = "You are..."
    r'system_message\s*=\s*["\']',      # e.g. system_message = "You are..."
]

# ── Injection bypass phrases that should never appear as string literals ───────
# We only flag these inside quoted strings, not inside comments or pattern defs
INJECTION_PHRASES = [
    "ignore previous instructions",
    "you are now",
    "pretend you are",
    "act as if you have no restrictions",
]

# ── Files to always skip ───────────────────────────────────────────────────────
EXCLUDED_FILES = {
    "inject_scanner.py",   # never scan the scanner itself
}

# ── Directories to skip ───────────────────────────────────────────────────────
EXCLUDED_DIRS = {
    ".git", "venv", "env", "ai-lab", "redteam-env", "__pycache__",
    ".github", "node_modules",
}


def is_comment_line(line):
    """Return True if the line is a Python comment (after stripping whitespace)."""
    return line.strip().startswith("#")


def is_injection_phrase_in_string(line, phrase):
    """
    Return True only if the injection phrase appears inside a quoted string.
    This avoids false positives from pattern definitions or comments.
    """
    # Look for the phrase inside single or double quoted strings
    pattern = r'(["\']).*?' + re.escape(phrase) + r'.*?\1'
    return bool(re.search(pattern, line, re.IGNORECASE))


def scan_file(filepath):
    """
    Scan a single .py file for forbidden patterns and phrases.
    Returns a list of (line_number, matched_text) tuples.
    """
    findings = []

    with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
        for line_num, line in enumerate(f, start=1):

            # Skip pure comment lines entirely
            if is_comment_line(line):
                continue

            # ── Check for hardcoded system prompt string literals ──────────
            for pattern in SYSTEM_PROMPT_PATTERNS:
                if re.search(pattern, line, re.IGNORECASE):
                    findings.append((
                        line_num,
                        f"[HARDCODED SYSTEM PROMPT] matched '{pattern}' → {line.strip()}"
                    ))

            # ── Check injection phrases (only inside quoted strings) ───────
            for phrase in INJECTION_PHRASES:
                if is_injection_phrase_in_string(line, phrase):
                    findings.append((
                        line_num,
                        f"[INJECTION PHRASE] '{phrase}' found in string → {line.strip()}"
                    ))

    return findings


def scan_repository(root_dir="."):
    """
    Walk the repository and scan every .py file (except excluded ones).
    Returns a dict of filepath → list of findings.
    """
    all_findings = {}

    for dirpath, dirnames, filenames in os.walk(root_dir):
        # Skip excluded directories in-place (modifying dirnames[:] prevents os.walk descending)
        dirnames[:] = [d for d in dirnames if d not in EXCLUDED_DIRS]

        for filename in filenames:
            if not filename.endswith(".py"):
                continue

            # Skip excluded files by name
            if filename in EXCLUDED_FILES:
                continue

            filepath = os.path.join(dirpath, filename)
            findings = scan_file(filepath)
            if findings:
                all_findings[filepath] = findings

    return all_findings


def main():
    print("=" * 60)
    print("  Prompt Injection Scanner — Gate 4")
    print("=" * 60)

    findings = scan_repository(".")

    if not findings:
        print("[PASS] No hardcoded system prompts or injection phrases found.")
        sys.exit(0)
    else:
        total = sum(len(v) for v in findings.values())
        print(f"[FAIL] Found {total} violation(s) in {len(findings)} file(s):\n")
        for filepath, issues in findings.items():
            print(f"  File: {filepath}")
            for line_num, description in issues:
                print(f"    Line {line_num}: {description}")
            print()
        sys.exit(1)


if __name__ == "__main__":
    main()