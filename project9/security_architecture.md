# Security Architecture Document — TechCorp Secure AI Application
## Project 9 — Capstone Integration

---

## Section 1: Authentication
- **File:** auth.py
- **Function:** token_required (decorator)
- **Threat Mitigated:** Unauthenticated access to the /chat endpoint
- **Implementation:** Reads JWT from Authorization: Bearer header. Verifies using HS256 algorithm against JWT_SECRET environment variable. Returns HTTP 401 for missing, expired, or invalid tokens. Secret is never hardcoded.

---

## Section 2: Input Validation
- **File:** validate.py
- **Function:** validate_input(user_input)
- **Threat Mitigated:** Prompt injection, jailbreak attempts, encoded payload attacks
- **Implementation:** Three-layer check: (1) rejects inputs over 500 characters, (2) regex blocklist matches 8 injection patterns including base64 strings, (3) blocks role-play bypass phrases. Returns HTTP 400 with error detail on any match.

---

## Section 3: Output Scanning
- **File:** validate.py
- **Function:** scan_output(response_text)
- **Threat Mitigated:** Sensitive data disclosure, system prompt leakage, credential exfiltration
- **Implementation:** Scans every model response before returning it. Blocks responses containing credential patterns (password=, api_key=, token=), SYSTEM PROMPT text, or unsolicited external URLs. Replaces blocked response with a safe error message.

---

## Section 4: Dependency Security
- **File:** requirements_pinned.txt
- **Tool:** pip-audit
- **Threat Mitigated:** Known CVE exploitation via vulnerable third-party packages
- **Implementation:** All packages pinned to exact versions in requirements_pinned.txt. pip-audit run against both unpinned baseline and pinned hardened file. CVE counts compared before and after. Any Critical/High CVEs resolved by version upgrade.

---

## Section 5: CI/CD Pipeline
- **File:** .github/workflows/security.yml
- **Script:** inject_scanner.py
- **Threat Mitigated:** Insecure code, secrets, vulnerable dependencies reaching production
- **Implementation:** Four sequential gates on every push: (1) Bandit SAST fails on High severity code issues, (2) Safety fails on Critical/High CVEs in requirements.txt, (3) Gitleaks fails on detected secrets/API keys, (4) Custom inject_scanner.py fails on hardcoded system prompts or injection bypass phrases in .py files.
