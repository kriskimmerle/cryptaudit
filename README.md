# cryptaudit

**Python Crypto Usage Auditor** — AST-based static analysis of cryptographic patterns.

20 rules covering weak hashing, insecure random, deprecated crypto libraries, ECB mode, hardcoded keys, SSL misconfig, timing attacks, and more. A dedicated crypto auditor with A-F grading.

## Why?

Bandit has ~5 crypto rules among hundreds of others. pylint has none. cryptaudit is *focused* on cryptographic correctness — 20 rules, actionable fix suggestions, and grading.

## Install

```bash
curl -O https://raw.githubusercontent.com/kriskimmerle/cryptaudit/main/cryptaudit.py
chmod +x cryptaudit.py
```

Python 3.9+, zero dependencies.

## Usage

```bash
python3 cryptaudit.py src/
python3 cryptaudit.py --verbose app.py
python3 cryptaudit.py --check B --no-color
python3 cryptaudit.py --json
python3 cryptaudit.py --list-rules
```

## Rules (20)

| ID | Severity | Name | Description |
|----|----------|------|-------------|
| CR001 | ERROR | weak-hash | MD5/SHA1 for security |
| CR002 | ERROR | insecure-random | `random` module for secrets |
| CR003 | ERROR | ecb-mode | ECB cipher mode |
| CR004 | ERROR | hardcoded-key | Hardcoded crypto keys |
| CR005 | ERROR | weak-key-size | RSA <2048 bits |
| CR006 | WARNING | no-password-hash | Plain hash for passwords |
| CR007 | ERROR | deprecated-crypto | PyCrypto (use pycryptodome) |
| CR008 | ERROR | ssl-no-verify | `verify=False` |
| CR009 | ERROR | weak-tls | SSLv2/v3/TLSv1.0 |
| CR010 | WARNING | timing-attack | `==` on secrets |
| CR011 | ERROR | hardcoded-iv | Hardcoded IV/nonce |
| CR012 | WARNING | base64-as-crypto | Base64 ≠ encryption |
| CR013 | ERROR | weak-cipher | DES, 3DES, RC4, Blowfish |
| CR014 | ERROR | hardcoded-password | Passwords in source code |
| CR015 | WARNING | pickle-deserialize | Pickle = code execution |
| CR016 | WARNING | yaml-unsafe-load | `yaml.load()` without Loader |
| CR017 | WARNING | eval-usage | eval()/exec() injection |
| CR018 | WARNING | assert-security | assert for auth checks |
| CR019 | INFO | temp-file-insecure | Predictable temp paths |
| CR020 | ERROR | jwt-no-verify | JWT without verification |

## Example

```
cryptaudit — Python Crypto Usage Auditor

  Grade: F (0/100)
  Findings: 18 error, 5 warning, 1 info

  bad_crypto.py
    ✖ [CR001] Weak hash function: MD5 :11
      Fix: Use hashlib.sha256() or hashlib.sha3_256()
    ✖ [CR002] Insecure random: random.randint :16
      Fix: Use secrets.token_hex() or secrets.randbelow()
    ✖ [CR003] ECB cipher mode :21
      Fix: Use CBC, GCM, or CTR mode
    ✖ [CR008] SSL/TLS certificate verification disabled :33
    ▲ [CR010] Timing-unsafe comparison of secret value :45
      Fix: Use hmac.compare_digest()
```

## CI Integration

```yaml
- name: Crypto audit
  run: python3 cryptaudit.py --check B --no-color src/
```

## License

MIT
