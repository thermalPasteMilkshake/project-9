"""
Project 5 - Custom prompt-injection / hardcoded-prompt scanner (Gate 4).

Searches all .py files in the repository for:
  - hardcoded system-prompt assignments: SYSTEM_PROMPT =, system_message =,
    and the "role": "system" message pattern
  - common injection bypass phrases

Exit code 1 if any match is found (fails the pipeline), 0 if clean.
Cross-platform (pure Python) - runs the same on Linux and Windows.

Usage:
    python inject_scanner.py [root_dir]     # default root = "."
"""

import os
import re
import sys

SYSTEM_PROMPT_PATTERNS = [
    r"SYSTEM_PROMPT\s*=",
    r"system_message\s*=",
    r'["\']role["\']\s*:\s*["\']system["\']',
]

INJECTION_PHRASES = [
    "ignore previous instructions",
    "you are now",
    "pretend you are",
    "act as if you have no restrictions",
]

# Don't scan the scanner itself or virtualenvs/VCS dirs.
SKIP_DIRS = {".git", ".venv", "venv", "ai-lab", "redteam-env", "__pycache__"}
SELF = os.path.basename(__file__)

# The defence modules legitimately contain the blocklist phrases (they are the
# controls that detect them), so they are not application prompt code.
SKIP_FILES = {"validate.py", "output_scanner.py"}

# A prompt assignment sourced from the environment is NOT a hardcoded prompt.
ALLOW_LINE = re.compile(r"os\.environ|getenv")

_sys_re = [re.compile(p) for p in SYSTEM_PROMPT_PATTERNS]


def scan_file(path):
    findings = []
    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            for lineno, line in enumerate(f, 1):
                env_based = ALLOW_LINE.search(line)
                for rx in _sys_re:
                    if rx.search(line) and not env_based:
                        findings.append((lineno, f"hardcoded prompt: {rx.pattern}", line.strip()))
                low = line.lower()
                for phrase in INJECTION_PHRASES:
                    if phrase in low:
                        findings.append((lineno, f"injection phrase: '{phrase}'", line.strip()))
    except OSError as e:
        print(f"[warn] could not read {path}: {e}")
    return findings


def main(root="."):
    total = 0
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
        for name in filenames:
            if not name.endswith(".py") or name == SELF or name in SKIP_FILES:
                continue
            path = os.path.join(dirpath, name)
            for lineno, reason, excerpt in scan_file(path):
                total += 1
                print(f"[FAIL] {path}:{lineno} {reason} -> {excerpt}")

    if total:
        print(f"\ninject_scanner: {total} issue(s) found.")
        return 1
    print("inject_scanner: clean - no hardcoded prompts or injection phrases found.")
    return 0


if __name__ == "__main__":
    root = sys.argv[1] if len(sys.argv) > 1 else "."
    sys.exit(main(root))
