"""Example: Bad cryptographic practices for testing cryptaudit."""

import hashlib
import random
import pickle
import yaml
import ssl
from Crypto.Cipher import AES, DES

# CR001: Weak hash
user_hash = hashlib.md5(b"password123").hexdigest()
token_hash = hashlib.sha1(b"secret_token").hexdigest()
weak = hashlib.new("md5", b"data")

# CR002: Insecure random for security
session_token = str(random.randint(0, 999999999))
api_key = ''.join([chr(random.randint(65, 90)) for _ in range(32)])
otp_pin = random.randrange(100000, 999999)

# CR003: ECB mode
cipher = AES.new(key, AES.MODE_ECB)

# CR004: Hardcoded key
secret_key = "my-super-secret-key-12345678"
cipher2 = AES.new(b"0123456789abcdef", AES.MODE_CBC, iv=iv)

# CR005: Weak RSA key
from Crypto.PublicKey import RSA
key = RSA.generate(1024)

# CR008: SSL no verify
import requests
response = requests.get("https://api.example.com", verify=False)

# CR009: Weak TLS
ctx = ssl.SSLContext(ssl.PROTOCOL_SSLv3)

# CR010: Timing attack
def check_token(provided, expected):
    if provided == expected:
        return True
    return False

secret = "abc123"
if token == secret:
    grant_access()

# CR011: Hardcoded IV
cipher3 = AES.new(key, AES.MODE_CBC, iv=b"0000000000000000")

# CR013: Weak cipher
des_cipher = DES.new(key8, DES.MODE_CBC)

# CR014: Hardcoded password
database_password = "p@ssw0rd_2024!"
mysql_password = "root_secret_123"

# CR015: Pickle
data = pickle.loads(user_input)

# CR016: Unsafe YAML
config = yaml.load(file_content)

# CR017: eval
result = eval(user_expression)

# CR018: Assert for auth
def check_admin(user):
    assert user.is_admin, "Not admin"
    return sensitive_data()

# CR019: Insecure temp file
import os
f = open("/tmp/secrets.txt", "w")
