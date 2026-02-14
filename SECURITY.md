# Security Best Practices

This guide explains the cryptographic security issues that cryptaudit detects and how to fix them.

## Quick Reference

### ❌ Don't Use

- `hashlib.md5()` - collision attacks
- `hashlib.sha1()` - deprecated, collisions found
- `random.random()` - predictable, not cryptographically secure
- `Crypto.Cipher.DES` - broken cipher
- `Crypto.Cipher.ARC4` / `RC4` - broken stream cipher
- `ssl.PROTOCOL_SSLv3` / `TLSv1` - vulnerable protocols

### ✅ Use Instead

- `hashlib.sha256()` or `hashlib.sha3_256()` for hashing
- `secrets.token_bytes()` / `secrets.token_hex()` for random values
- `Crypto.Cipher.AES` with GCM or CBC mode
- `ssl.PROTOCOL_TLS` or `ssl.create_default_context()`

## Detailed Issues

### 1. Weak Hashing (MD5, SHA1)

**Why it's bad:**
MD5 and SHA1 are broken. Attackers can create collisions (different inputs that produce the same hash).

**Bad:**
```python
import hashlib

password = "user_password"
hash = hashlib.md5(password.encode()).hexdigest()  # Broken!
```

**Good:**
```python
import hashlib
import secrets

password = "user_password"
salt = secrets.token_bytes(16)
hash = hashlib.pbkdf2_hmac('sha256', password.encode(), salt, 100000)
```

For password hashing, use `bcrypt`, `argon2`, or `scrypt`:
```python
import bcrypt

password = b"user_password"
hashed = bcrypt.hashpw(password, bcrypt.gensalt())
```

### 2. Insecure Random Number Generation

**Why it's bad:**
`random.random()` is predictable. If used for tokens, session IDs, or keys, attackers can guess values.

**Bad:**
```python
import random

session_id = random.randint(1000000, 9999999)  # Predictable!
api_key = ''.join(random.choices('abcdef0123456789', k=32))  # Guessable!
```

**Good:**
```python
import secrets

session_id = secrets.randbelow(10000000)
api_key = secrets.token_hex(16)  # 32 hex chars, cryptographically secure
reset_token = secrets.token_urlsafe(32)
```

### 3. Weak Ciphers (DES, RC4, 3DES)

**Why it's bad:**
DES has a 56-bit key (brute-forceable in minutes). RC4 has known biases. 3DES is slow and deprecated.

**Bad:**
```python
from Crypto.Cipher import DES, ARC4

cipher = DES.new(key, DES.MODE_ECB)  # Broken!
cipher = ARC4.new(key)  # Broken!
```

**Good:**
```python
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

key = get_random_bytes(32)  # 256-bit key
nonce = get_random_bytes(12)
cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
ciphertext, tag = cipher.encrypt_and_digest(plaintext)
```

### 4. Insecure SSL/TLS

**Why it's bad:**
SSLv2, SSLv3, TLS 1.0, and TLS 1.1 have known vulnerabilities (POODLE, BEAST, etc.).

**Bad:**
```python
import ssl

context = ssl.SSLContext(ssl.PROTOCOL_SSLv3)  # Vulnerable!
context = ssl.SSLContext(ssl.PROTOCOL_TLSv1)  # Deprecated!
```

**Good:**
```python
import ssl

# Use default secure context
context = ssl.create_default_context()

# Or explicitly set minimum version
context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
context.minimum_version = ssl.TLSVersion.TLSv1_2
```

### 5. ECB Mode (Block Cipher Mode)

**Why it's bad:**
ECB mode encrypts identical plaintext blocks to identical ciphertext blocks, revealing patterns.

**Bad:**
```python
from Crypto.Cipher import AES

cipher = AES.new(key, AES.MODE_ECB)  # Leaks patterns!
```

**Good:**
```python
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

# GCM mode (authenticated encryption)
key = get_random_bytes(32)
nonce = get_random_bytes(12)
cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)

# Or CBC with HMAC
from Crypto.Util.Padding import pad
iv = get_random_bytes(16)
cipher = AES.new(key, AES.MODE_CBC, iv)
ciphertext = cipher.encrypt(pad(plaintext, AES.block_size))
```

### 6. Hardcoded Keys and Secrets

**Why it's bad:**
Keys in source code end up in version control, logs, and binaries. Anyone with code access has the keys.

**Bad:**
```python
API_KEY = "sk-1234567890abcdef"  # Leaked!
SECRET_KEY = b"my_secret_encryption_key_123"  # In git history!
```

**Good:**
```python
import os

API_KEY = os.environ['API_KEY']
SECRET_KEY = os.environ.get('SECRET_KEY')

# Or use a secrets manager
import boto3
secrets_client = boto3.client('secretsmanager')
secret = secrets_client.get_secret_value(SecretId='my-api-key')
API_KEY = secret['SecretString']
```

### 7. Certificate Verification Disabled

**Why it's bad:**
Disabling certificate checks allows man-in-the-middle attacks.

**Bad:**
```python
import requests

response = requests.get('https://api.example.com', verify=False)  # MITM risk!

import ssl
context = ssl._create_unverified_context()  # Dangerous!
```

**Good:**
```python
import requests

# Verify by default
response = requests.get('https://api.example.com')

# Or specify CA bundle
response = requests.get('https://api.example.com', verify='/path/to/ca-bundle.crt')

import ssl
context = ssl.create_default_context()  # Verifies certs
```

## Testing Your Fixes

After fixing issues:

```bash
# Re-run cryptaudit
cryptaudit path/to/code/

# Should show improved score
# Before: F (multiple critical issues)
# After: A (no issues found)
```

## Additional Resources

- [OWASP Cryptographic Storage Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cryptographic_Storage_Cheat_Sheet.html)
- [Python Cryptography Documentation](https://cryptography.io/)
- [NIST Cryptographic Standards](https://csrc.nist.gov/projects/cryptographic-standards-and-guidelines)
- [Mozilla SSL Configuration Generator](https://ssl-config.mozilla.org/)

## When to Use cryptaudit

- **Pre-commit**: Catch issues before they reach production
- **Code review**: Automated security check in CI/CD
- **Security audit**: Periodic scans of codebase
- **Dependency updates**: Check if new code introduces weak crypto
- **Compliance**: Verify FIPS, PCI-DSS, or other standards

## Limitations

cryptaudit detects patterns in code, not runtime behavior. It may:

- **Miss**: Dynamic cipher selection, reflection-based calls, obfuscated code
- **False positives**: MD5 used for non-security purposes (checksums, cache keys)

For comprehensive security, combine with:
- Manual security review
- Penetration testing
- Dependency scanning (pip-audit, safety)
- SAST tools (bandit, semgrep)

## Contributing

Found a new weak crypto pattern? Open an issue or PR:
https://github.com/kriskimmerle/cryptaudit
