import os
import functools

import requests
import jwt
from flask import Flask, request, jsonify

from validate import validate_input
from output_scanner import scan_output

app = Flask(__name__)

JWT_SECRET = os.environ.get("JWT_SECRET")
JWT_ALGO = "HS256"

OLLAMA_URL = os.environ.get("OLLAMA_URL", "http://localhost:11434/api/generate")
MODEL = os.environ.get("OLLAMA_MODEL", "llama3.2:3b")

SYSTEM_PROMPT = os.environ.get("SYSTEM_PROMPT", "You are TechCorp Assistant.")

SAFE_OUTPUT_ERROR = "Response withheld by output policy."

# Prompt-injection defence layer (Project 2) is ON by default. It can be disabled
# ONLY to produce the before/after demonstration evidence: DEFENCE=off python app.py
# JWT authentication is unaffected by this flag and is always enforced.
DEFENCE = os.environ.get("DEFENCE", "on").lower() != "off"


def token_required(fn):
    @functools.wraps(fn)
    def wrapper(*args, **kwargs):
        if not JWT_SECRET:
            return jsonify({"error": "server misconfigured: JWT_SECRET not set"}), 500

        auth = request.headers.get("Authorization", "")
        if not auth.startswith("Bearer "):
            return jsonify({"error": "missing or malformed Authorization header"}), 401

        token = auth.split(" ", 1)[1].strip()
        try:
            jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGO])
        except jwt.ExpiredSignatureError:
            return jsonify({"error": "token expired"}), 401
        except jwt.InvalidTokenError:
            return jsonify({"error": "invalid token"}), 401

        return fn(*args, **kwargs)

    return wrapper


def call_model(user_message):
    prompt = f"{SYSTEM_PROMPT}\n\nUser: {user_message}\nAssistant:"
    try:
        r = requests.post(
            OLLAMA_URL,
            json={"model": MODEL, "prompt": prompt, "stream": False},
            timeout=120,
        )
        r.raise_for_status()
        return r.json().get("response", "")
    except requests.exceptions.RequestException as e:
        return f"[Ollama unavailable: {e}] You said: {user_message}"


@app.route("/chat", methods=["POST"])
@token_required
def chat():
    data = request.get_json(silent=True) or {}
    user_message = data.get("message", "")

    if DEFENCE:
        ok, reason = validate_input(user_message)
        if not ok:
            return jsonify({"error": reason, "blocked_by": "input-validation"}), 400

    answer = call_model(user_message)

    if DEFENCE:
        safe, _ = scan_output(answer)
        if not safe:
            return jsonify({"response": SAFE_OUTPUT_ERROR, "blocked_by": "output-scanner"}), 200

    return jsonify({"response": answer})


@app.route("/health")
def health():
    return jsonify({"status": "ok", "auth": "jwt", "defence": "on" if DEFENCE else "off"})


if __name__ == "__main__":
    port = int(os.environ.get("PORT", "5000"))
    print(f"[*] JWT auth: ENFORCED  |  Prompt-injection defence: {'ON' if DEFENCE else 'OFF'}")
    app.run(host="127.0.0.1", port=port, debug=False)
