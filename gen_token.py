"""
Mint a short-lived JWT for testing the /chat endpoint.

Usage:
  Linux/Kali:  export JWT_SECRET="change-me" ; python gen_token.py
  Windows PS:  $env:JWT_SECRET="change-me" ; python gen_token.py

Prints the token; use it as:  Authorization: Bearer <token>
"""

import os
import sys
import datetime

import jwt

JWT_SECRET = os.environ.get("JWT_SECRET")
if not JWT_SECRET:
    sys.exit("JWT_SECRET not set in the environment.")

now = datetime.datetime.now(datetime.timezone.utc)
payload = {
    "sub": "test-user",
    "iat": now,
    "exp": now + datetime.timedelta(hours=1),
}

token = jwt.encode(payload, JWT_SECRET, algorithm="HS256")
# PyJWT >= 2 returns str; older returns bytes.
print(token if isinstance(token, str) else token.decode())
