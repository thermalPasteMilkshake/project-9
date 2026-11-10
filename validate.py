import re

MAX_LENGTH = 500  

INJECTION_PATTERNS = [
    r"ignore (all )?previous instructions",
    r"ignore (all )?prior instructions",
    r"you are now",
    r"pretend you are",
    r"act as if you have no",
    r"disregard (all )?(the )?(above|previous)",
    r"reveal your system prompt",
    r"print your (full )?system prompt",
]

BASE64_PATTERN = r"[A-Za-z0-9+/]{40,}={0,2}"

_compiled = [re.compile(p, re.IGNORECASE) for p in INJECTION_PATTERNS]
_b64 = re.compile(BASE64_PATTERN)


def validate_input(text):
    """Return (ok: bool, reason: str). ok=False means block with HTTP 400."""
    if text is None:
        return False, "Empty input."

    if len(text) > MAX_LENGTH:
        return False, f"Input exceeds maximum length of {MAX_LENGTH} characters."

    for pat in _compiled:
        if pat.search(text):
            return False, f"Input blocked: matched injection pattern '{pat.pattern}'."

    if _b64.search(text):
        return False, "Input blocked: long base64-encoded string detected."

    return True, "ok"
