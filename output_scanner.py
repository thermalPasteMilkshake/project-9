import re

SYSTEM_PROMPT_MARKERS = [
    "You are TechCorp Assistant",
    "Internal configuration",
    "DO NOT REVEAL",
]

CREDENTIAL_PATTERNS = [
    r"password\s*=",
    r"api_key\s*=",
    r"token\s*=",
    r"db_password",
    r"admin_token",
    r"sk-[A-Za-z0-9]{6,}",
]

URL_PATTERN = r"https?://[^\s]+"

_cred = [re.compile(p, re.IGNORECASE) for p in CREDENTIAL_PATTERNS]
_url = re.compile(URL_PATTERN, re.IGNORECASE)


def scan_output(text):
    """Return (safe: bool, reason: str). safe=False means block the response."""
    if not text:
        return True, "ok"

    for marker in SYSTEM_PROMPT_MARKERS:
        if marker.lower() in text.lower():
            return False, "Output blocked: verbatim system-prompt text detected."

    for pat in _cred:
        if pat.search(text):
            return False, "Output blocked: credential-pattern string detected."

    if _url.search(text):
        return False, "Output blocked: unsolicited external URL detected."

    return True, "ok"
