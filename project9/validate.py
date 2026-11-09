import re

# ── Layer 1: Max input length ──────────────────────────────────────────────────
MAX_INPUT_LENGTH = 500

# ── Layer 2: Regex injection blocklist ────────────────────────────────────────
INJECTION_PATTERNS = [
    r"ignore\s+(all\s+)?previous\s+instructions",
    r"you\s+are\s+now",
    r"pretend\s+you\s+are",
    r"act\s+as\s+if\s+you\s+have\s+no",
    r"[A-Za-z0-9+/]{40,}={0,2}",   # base64 strings of 40+ chars
    r"dan\s+mode",
    r"jailbreak",
    r"disregard\s+(all\s+)?(prior|previous)",
]

# ── Layer 3: Output scanner patterns ──────────────────────────────────────────
OUTPUT_BLOCK_PATTERNS = [
    r"password\s*=",
    r"api[_\s]?key\s*=",
    r"token\s*=",
    r"SYSTEM PROMPT",
    r"system_message\s*=",
    r"https?://[^\s]{20,}",         # unsolicited long external URLs
]

def validate_input(user_input: str):
    """
    Validates user input against all 3 layers.
    Returns (True, None) if clean, or (False, error_message) if blocked.
    """
    # Layer 1 — Length check
    if len(user_input) > MAX_INPUT_LENGTH:
        return False, f"Input too long ({len(user_input)} chars). Maximum allowed is {MAX_INPUT_LENGTH}."

    # Layer 2 — Injection blocklist
    for pattern in INJECTION_PATTERNS:
        if re.search(pattern, user_input, re.IGNORECASE):
            return False, f"Blocked: input matches injection pattern."

    return True, None


def scan_output(response_text: str):
    """
    Scans model output for sensitive data leakage.
    Returns (True, None) if clean, or (False, error_message) if blocked.
    """
    for pattern in OUTPUT_BLOCK_PATTERNS:
        if re.search(pattern, response_text, re.IGNORECASE):
            return False, "Response blocked: contains sensitive or disallowed content."

    return True, None