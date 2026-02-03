"""Example: Good cryptographic practices."""

import hashlib
import hmac
import secrets
import ssl
import tempfile
import json

# Strong hashing
data_hash = hashlib.sha256(b"data").hexdigest()
file_hash = hashlib.sha3_256(b"content").hexdigest()

# Cryptographic random
session_token = secrets.token_urlsafe(32)
api_key = secrets.token_hex(32)
otp = secrets.randbelow(1000000)

# Proper SSL
ctx = ssl.create_default_context()

# Timing-safe comparison
def verify_token(provided: str, expected: str) -> bool:
    return hmac.compare_digest(provided, expected)

# Safe YAML loading
import yaml
config = yaml.safe_load(file_content)

# Safe deserialization
data = json.loads(user_input)

# Secure temp files
with tempfile.NamedTemporaryFile(mode='w', delete=True) as f:
    f.write("sensitive data")

# Auth with proper exception
def check_admin(user):
    if not user.is_admin:
        raise PermissionError("Not admin")
    return sensitive_data()
