# AI Code Manifest
Generated: 2026-10-12T17:17:49Z | Tool: mantis v0.1.0 | Tier: standard

## Risk Summary
🔴 CRITICAL: 1 | 🟡 HIGH: 0 | 🟠 MEDIUM: 0 | 🟢 LOW: 0 | ℹ️ INFO: 0

## Overall: 🔴 FAIL
Reason: 1 critical in adversarial

## Change Profile
- Files changed: 9 (7 Python, 1 Toml)
- Lines added: 475 | Lines removed: 139

## Findings by Domain

### 🔴 Adversarial (1 findings)

| Sev | File | Line | Finding | Rule |
|-----|------|------|---------|------|
| CRITICAL | src/linux_mcp_server/auth_spiffe.py | 21 | compile() with obfuscated input (decode) | ADV-005 |

**ADV-005 — False positive.** Line 21 is `re.compile(r"^spiffe://([^/]+)/(.+)$")` — a static literal regex for validating SPIFFE ID format per the [SPIFFE spec](https://github.com/spiffe/spiffe/blob/main/standards/SPIFFE-ID.md). No user input, no decode, no obfuscation. Mantis flags any `compile()` call near string manipulation as a potential adversarial injection vector, but this is a constant pattern compiled once at module load.
