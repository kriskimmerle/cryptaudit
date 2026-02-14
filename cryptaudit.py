#!/usr/bin/env python3
"""cryptaudit — Python Crypto Usage Auditor.

AST-based static analysis of cryptographic code patterns.
Finds weak hashing, insecure random, deprecated crypto,
ECB mode, hardcoded keys, and more.

Zero dependencies. Python 3.9+.

Usage:
    cryptaudit [PATH]             Scan file or directory
    cryptaudit --json             JSON output
    cryptaudit --check [GRADE]    CI mode (exit 1 if below grade)
    cryptaudit --verbose          Show fix suggestions
    cryptaudit --list-rules       List all rules
"""

from __future__ import annotations

import argparse
import ast
import json
import os
import re
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional


__version__ = "0.1.0"


# ── Severity ──────────────────────────────────────────────────────────────────

class Severity:
    ERROR = "ERROR"
    WARNING = "WARNING"
    INFO = "INFO"

    _order = {"ERROR": 2, "WARNING": 1, "INFO": 0}

    @classmethod
    def weight(cls, s: str) -> int:
        return cls._order.get(s, 0)


# ── Finding ───────────────────────────────────────────────────────────────────

@dataclass
class Finding:
    rule_id: str
    severity: str
    message: str
    file: str
    line: int
    col: int = 0
    context: Optional[str] = None
    fix: Optional[str] = None

    def to_dict(self) -> dict:
        d = {
            "rule_id": self.rule_id,
            "severity": self.severity,
            "message": self.message,
            "file": self.file,
            "line": self.line,
        }
        if self.col:
            d["col"] = self.col
        if self.context:
            d["context"] = self.context
        if self.fix:
            d["fix"] = self.fix
        return d


# ── Rules ─────────────────────────────────────────────────────────────────────

RULES: dict[str, dict] = {
    "CR001": {
        "name": "weak-hash",
        "severity": Severity.ERROR,
        "description": "Weak hash function (MD5, SHA1) used for security-sensitive operation",
    },
    "CR002": {
        "name": "insecure-random",
        "severity": Severity.ERROR,
        "description": "Non-cryptographic random used where secrets module should be used",
    },
    "CR003": {
        "name": "ecb-mode",
        "severity": Severity.ERROR,
        "description": "ECB cipher mode is insecure (no diffusion)",
    },
    "CR004": {
        "name": "hardcoded-key",
        "severity": Severity.ERROR,
        "description": "Hardcoded cryptographic key or secret",
    },
    "CR005": {
        "name": "weak-key-size",
        "severity": Severity.ERROR,
        "description": "Cryptographic key size too small",
    },
    "CR006": {
        "name": "no-password-hash",
        "severity": Severity.WARNING,
        "description": "Password hashing without proper KDF (bcrypt, scrypt, argon2, PBKDF2)",
    },
    "CR007": {
        "name": "deprecated-crypto",
        "severity": Severity.ERROR,
        "description": "Using deprecated/insecure cryptographic library",
    },
    "CR008": {
        "name": "ssl-no-verify",
        "severity": Severity.ERROR,
        "description": "SSL/TLS certificate verification disabled",
    },
    "CR009": {
        "name": "weak-tls",
        "severity": Severity.ERROR,
        "description": "Weak SSL/TLS protocol version (SSLv2, SSLv3, TLSv1.0)",
    },
    "CR010": {
        "name": "timing-attack",
        "severity": Severity.WARNING,
        "description": "String comparison on secrets (use hmac.compare_digest instead)",
    },
    "CR011": {
        "name": "hardcoded-iv",
        "severity": Severity.ERROR,
        "description": "Hardcoded initialization vector (IV/nonce)",
    },
    "CR012": {
        "name": "base64-as-crypto",
        "severity": Severity.WARNING,
        "description": "Base64 encoding used as if it were encryption",
    },
    "CR013": {
        "name": "weak-cipher",
        "severity": Severity.ERROR,
        "description": "Weak or deprecated cipher algorithm (DES, 3DES, RC4, Blowfish)",
    },
    "CR014": {
        "name": "hardcoded-password",
        "severity": Severity.ERROR,
        "description": "Hardcoded password in source code",
    },
    "CR015": {
        "name": "pickle-deserialize",
        "severity": Severity.WARNING,
        "description": "Pickle deserialization of untrusted data (arbitrary code execution)",
    },
    "CR016": {
        "name": "yaml-unsafe-load",
        "severity": Severity.WARNING,
        "description": "yaml.load() without safe Loader (arbitrary code execution)",
    },
    "CR017": {
        "name": "eval-usage",
        "severity": Severity.WARNING,
        "description": "eval()/exec() used — potential code injection",
    },
    "CR018": {
        "name": "assert-security",
        "severity": Severity.WARNING,
        "description": "assert used for security check (disabled with python -O)",
    },
    "CR019": {
        "name": "temp-file-insecure",
        "severity": Severity.INFO,
        "description": "Insecure temporary file creation (use tempfile module)",
    },
    "CR020": {
        "name": "jwt-no-verify",
        "severity": Severity.ERROR,
        "description": "JWT decoded without verification",
    },
    "CR021": {
        "name": "weak-pbkdf2-iterations",
        "severity": Severity.WARNING,
        "description": "PBKDF2 iteration count is too low (< 100,000)",
    },
}


# ── AST Helpers ───────────────────────────────────────────────────────────────

def get_name(node: ast.expr) -> str:
    """Get the full dotted name from an expression."""
    if isinstance(node, ast.Name):
        return node.id
    elif isinstance(node, ast.Attribute):
        val = get_name(node.value)
        return f"{val}.{node.attr}" if val else node.attr
    elif isinstance(node, ast.Constant):
        return str(node.value)
    return ""


def get_string_value(node: ast.expr) -> Optional[str]:
    """Get string value from a Constant node."""
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    return None


def is_bytes_literal(node: ast.expr) -> bool:
    """Check if node is a bytes literal."""
    return isinstance(node, ast.Constant) and isinstance(node.value, bytes)


def get_keyword_arg(call: ast.Call, name: str) -> Optional[ast.expr]:
    """Get a keyword argument from a function call."""
    for kw in call.keywords:
        if kw.arg == name:
            return kw.value
    return None


# ── Analyzer ──────────────────────────────────────────────────────────────────

class CryptoAnalyzer(ast.NodeVisitor):
    """AST visitor that analyzes cryptographic usage patterns."""

    def __init__(self, file_path: str, source_lines: list[str], ignored: set[str]):
        self.file_path = file_path
        self.source_lines = source_lines
        self.ignored = ignored
        self.findings: list[Finding] = []
        self._imports: dict[str, str] = {}  # alias -> full module name

    def _add(self, rule_id: str, node: ast.AST, message: str,
             context: Optional[str] = None, fix: Optional[str] = None) -> None:
        if rule_id in self.ignored:
            return
        rule = RULES[rule_id]
        line = getattr(node, "lineno", 0)
        col = getattr(node, "col_offset", 0)

        if context is None and 0 < line <= len(self.source_lines):
            context = self.source_lines[line - 1].rstrip()
            if len(context) > 120:
                context = context[:117] + "..."

        self.findings.append(Finding(
            rule_id=rule_id,
            severity=rule["severity"],
            message=message,
            file=self.file_path,
            line=line,
            col=col,
            context=context,
            fix=fix,
        ))

    def visit_Import(self, node: ast.Import) -> None:
        for alias in node.names:
            name = alias.asname or alias.name
            self._imports[name] = alias.name

            # CR007: Deprecated crypto library
            if "CR007" not in self.ignored:
                if alias.name in ("Crypto", "pycrypto"):
                    self._add("CR007", node,
                              f"Deprecated library: {alias.name} (use pycryptodome/cryptography instead)",
                              fix="Replace `from Crypto` with `from Cryptodome` (pycryptodome) or use `cryptography`")
                elif alias.name == "Cryptodome" and False:
                    pass  # pycryptodome is OK

        self.generic_visit(node)

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        module = node.module or ""
        for alias in node.names:
            name = alias.asname or alias.name
            self._imports[name] = f"{module}.{alias.name}"

        # CR007: Deprecated crypto imports
        if "CR007" not in self.ignored:
            if module.startswith("Crypto.") and not module.startswith("Cryptodome."):
                self._add("CR007", node,
                          f"Deprecated library: {module}",
                          fix="Use pycryptodome (`from Cryptodome...`) or `cryptography` library")

        self.generic_visit(node)

    def visit_Call(self, node: ast.Call) -> None:
        func_name = get_name(node.func)

        # ── CR001: Weak hash ──────────────────────────────────────────────
        if "CR001" not in self.ignored:
            weak_hashes = {
                "hashlib.md5": "MD5",
                "hashlib.sha1": "SHA1",
                "MD5.new": "MD5",
                "SHA.new": "SHA1",
                "SHA1.new": "SHA1",
                "Crypto.Hash.MD5.new": "MD5",
                "Crypto.Hash.SHA.new": "SHA1",
                "Cryptodome.Hash.MD5.new": "MD5",
                "Cryptodome.Hash.SHA.new": "SHA1",
            }
            for pattern, algo in weak_hashes.items():
                if func_name.endswith(pattern) or func_name == pattern:
                    self._add("CR001", node,
                              f"Weak hash function: {algo}",
                              fix=f"Use hashlib.sha256() or hashlib.sha3_256() instead of {algo}")
                    break

            # Also check: hashlib.new("md5") / hashlib.new("sha1")
            if func_name.endswith("hashlib.new") or func_name == "hashlib.new":
                if node.args:
                    algo_arg = get_string_value(node.args[0])
                    if algo_arg and algo_arg.lower() in ("md5", "sha1", "sha"):
                        self._add("CR001", node,
                                  f"Weak hash function: {algo_arg.upper()}",
                                  fix="Use 'sha256' or 'sha3_256' instead")

        # ── CR002: Insecure random ────────────────────────────────────────
        if "CR002" not in self.ignored:
            insecure_randoms = {
                "random.random", "random.randint", "random.randrange",
                "random.choice", "random.sample", "random.getrandbits",
                "random.uniform", "random.shuffle",
            }
            if func_name in insecure_randoms:
                # Heuristic: check if used in security context
                # Look for security-related variable names in assignment
                parent_context = self._get_parent_context(node)
                if parent_context:
                    self._add("CR002", node,
                              f"Insecure random: {func_name}",
                              fix="Use secrets.token_hex(), secrets.token_urlsafe(), or secrets.randbelow()")

        # ── CR003: ECB mode ───────────────────────────────────────────────
        if "CR003" not in self.ignored:
            # Check for MODE_ECB or ECB in cipher creation
            for arg in node.args:
                name = get_name(arg)
                if "ECB" in name or "MODE_ECB" in name:
                    self._add("CR003", node,
                              "ECB cipher mode: identical plaintext blocks produce identical ciphertext",
                              fix="Use CBC, GCM, or CTR mode instead of ECB")
                    break

            # Check keyword args
            mode_kw = get_keyword_arg(node, "mode")
            if mode_kw:
                mode_name = get_name(mode_kw)
                if "ECB" in mode_name:
                    self._add("CR003", node,
                              "ECB cipher mode specified",
                              fix="Use CBC, GCM, or CTR mode instead of ECB")

        # ── CR004/CR011: Hardcoded key/IV ─────────────────────────────────
        if "CR004" not in self.ignored or "CR011" not in self.ignored:
            cipher_funcs = {"AES.new", "DES.new", "DES3.new", "Blowfish.new",
                           "ARC4.new", "ChaCha20.new", "Salsa20.new",
                           "Cipher", "Fernet"}
            if any(func_name.endswith(f) for f in cipher_funcs):
                # Check first arg (key) for hardcoded value
                if node.args and "CR004" not in self.ignored:
                    if isinstance(node.args[0], ast.Constant):
                        self._add("CR004", node,
                                  "Hardcoded cryptographic key",
                                  fix="Load keys from environment variables, key vault, or secure config")

                # Check IV/nonce keyword
                if "CR011" not in self.ignored:
                    for kw_name in ("iv", "IV", "nonce"):
                        kw = get_keyword_arg(node, kw_name)
                        if kw and isinstance(kw, ast.Constant):
                            self._add("CR011", node,
                                      f"Hardcoded initialization vector ({kw_name})",
                                      fix="Generate random IV: os.urandom(16) or secrets.token_bytes(16)")

        # ── CR005: Weak key size ──────────────────────────────────────────
        if "CR005" not in self.ignored:
            # RSA key generation
            if "generate" in func_name.lower() or "rsa" in func_name.lower():
                for arg in node.args:
                    if isinstance(arg, ast.Constant) and isinstance(arg.value, int):
                        if arg.value < 2048:
                            self._add("CR005", node,
                                      f"RSA key size too small: {arg.value} bits",
                                      fix="Use at least 2048 bits (recommended: 4096)")

                bits_kw = get_keyword_arg(node, "bits") or get_keyword_arg(node, "key_size")
                if bits_kw and isinstance(bits_kw, ast.Constant) and isinstance(bits_kw.value, int):
                    if bits_kw.value < 2048:
                        self._add("CR005", node,
                                  f"Key size too small: {bits_kw.value} bits",
                                  fix="Use at least 2048 bits for RSA, 256 bits for symmetric")

        # ── CR008: SSL verify=False ───────────────────────────────────────
        if "CR008" not in self.ignored:
            verify_kw = get_keyword_arg(node, "verify")
            if verify_kw:
                if isinstance(verify_kw, ast.Constant) and verify_kw.value is False:
                    self._add("CR008", node,
                              "SSL/TLS certificate verification disabled",
                              fix="Remove verify=False or configure proper CA certificates")

            # ssl._create_unverified_context
            if "_create_unverified_context" in func_name:
                self._add("CR008", node,
                          "Creating unverified SSL context",
                          fix="Use ssl.create_default_context() for proper verification")

        # ── CR009: Weak TLS ───────────────────────────────────────────────
        if "CR009" not in self.ignored:
            for arg in node.args:
                name = get_name(arg)
                if any(weak in name for weak in ["PROTOCOL_SSLv2", "PROTOCOL_SSLv3",
                                                  "PROTOCOL_TLSv1", "PROTOCOL_TLS"
                                                  ]):
                    # PROTOCOL_TLS without the version suffix is actually OK (auto-negotiate)
                    if name.endswith("PROTOCOL_TLS"):
                        continue
                    if "SSLv" in name or name.endswith("PROTOCOL_TLSv1"):
                        self._add("CR009", node,
                                  f"Weak TLS/SSL protocol: {name}",
                                  fix="Use ssl.PROTOCOL_TLS_CLIENT (Python 3.6+)")

            # Check for minimum_version
            for kw in node.keywords:
                if kw.arg in ("protocol",):
                    val_name = get_name(kw.value)
                    if "SSLv" in val_name or val_name.endswith("TLSv1"):
                        self._add("CR009", node,
                                  f"Weak TLS protocol: {val_name}",
                                  fix="Use TLSVersion.TLSv1_2 or higher")

        # ── CR013: Weak cipher ────────────────────────────────────────────
        if "CR013" not in self.ignored:
            weak_ciphers = {"DES", "DES3", "3DES", "TripleDES", "RC2", "RC4",
                           "ARC4", "Blowfish", "IDEA", "CAST5"}
            for wc in weak_ciphers:
                if wc in func_name:
                    self._add("CR013", node,
                              f"Weak cipher: {wc}",
                              fix="Use AES-256 (AES with 256-bit key) or ChaCha20")
                    break

        # ── CR015: Pickle ─────────────────────────────────────────────────
        if "CR015" not in self.ignored:
            if func_name in ("pickle.loads", "pickle.load", "cPickle.loads", "cPickle.load"):
                self._add("CR015", node,
                          "Pickle deserialization — arbitrary code execution risk",
                          fix="Use JSON, MessagePack, or Protocol Buffers for untrusted data")

        # ── CR016: yaml.load ──────────────────────────────────────────────
        if "CR016" not in self.ignored:
            if func_name in ("yaml.load", "yaml.unsafe_load"):
                loader_kw = get_keyword_arg(node, "Loader")
                if loader_kw is None and func_name == "yaml.load":
                    self._add("CR016", node,
                              "yaml.load() without explicit Loader",
                              fix="Use yaml.safe_load() or yaml.load(data, Loader=yaml.SafeLoader)")
                elif func_name == "yaml.unsafe_load":
                    self._add("CR016", node,
                              "yaml.unsafe_load() — arbitrary code execution risk",
                              fix="Use yaml.safe_load() instead")

        # ── CR017: eval/exec ──────────────────────────────────────────────
        if "CR017" not in self.ignored:
            if func_name in ("eval", "exec"):
                self._add("CR017", node,
                          f"{func_name}() — potential code injection",
                          fix=f"Avoid {func_name}() with untrusted input. Use ast.literal_eval() for data parsing")

        # ── CR020: JWT no verify ──────────────────────────────────────────
        if "CR020" not in self.ignored:
            if "decode" in func_name and "jwt" in func_name.lower():
                # Check for options={"verify_signature": False}
                options_kw = get_keyword_arg(node, "options")
                verify_kw = get_keyword_arg(node, "verify")
                algorithms_kw = get_keyword_arg(node, "algorithms")

                if verify_kw and isinstance(verify_kw, ast.Constant) and verify_kw.value is False:
                    self._add("CR020", node,
                              "JWT decoded without signature verification",
                              fix="Remove verify=False or use proper verification")
                elif algorithms_kw is None and options_kw is None:
                    # PyJWT >= 2.0 requires algorithms parameter
                    pass  # Don't flag — might be using default verification

        # ── CR021: Weak PBKDF2 iterations ─────────────────────────────────
        if "CR021" not in self.ignored:
            # Check for PBKDF2 with low iteration count
            pbkdf2_patterns = ["pbkdf2", "PBKDF2", "pbkdf2_hmac"]
            if any(pattern in func_name for pattern in pbkdf2_patterns):
                # PBKDF2 typically has signature: pbkdf2_hmac(hash_name, password, salt, iterations)
                # or: PBKDF2(password, salt, dkLen, iterations)
                # Check for iterations argument (usually 3rd or 4th positional, or 'iterations'/'count' keyword)
                iterations = None
                
                # Check keyword arguments first
                iterations_kw = get_keyword_arg(node, "iterations") or get_keyword_arg(node, "count")
                if iterations_kw and isinstance(iterations_kw, ast.Constant):
                    iterations = iterations_kw.value
                # Check positional arguments (iterations usually at index 3 for pbkdf2_hmac)
                elif len(node.args) >= 4 and isinstance(node.args[3], ast.Constant):
                    iterations = node.args[3].value
                
                # NIST recommends minimum 100,000 iterations for PBKDF2-HMAC-SHA256
                if iterations is not None and isinstance(iterations, int):
                    if iterations < 100_000:
                        self._add("CR021", node,
                                  f"PBKDF2 iteration count too low: {iterations:,} (recommended: >= 100,000)",
                                  fix=f"Increase iterations to at least 100,000 (NIST SP 800-132 recommendation)")

        # ── CR006: Password hashing ───────────────────────────────────────
        if "CR006" not in self.ignored:
            # Check if hashing is used in password context
            if func_name in ("hashlib.sha256", "hashlib.sha512", "hashlib.sha3_256"):
                # Check if variable name suggests password context
                pass  # Too many false positives from just the call alone

        self.generic_visit(node)

    def visit_Compare(self, node: ast.Compare) -> None:
        """Detect timing-unsafe string comparisons on secrets."""
        if "CR010" not in self.ignored:
            # Look for: secret == value, token == expected, etc.
            left_name = get_name(node.left).lower() if isinstance(node.left, (ast.Name, ast.Attribute)) else ""
            secret_words = {"secret", "token", "password", "key", "hash", "digest",
                           "signature", "mac", "hmac", "api_key", "apikey", "auth"}

            is_secret_compare = any(w in left_name for w in secret_words)

            if not is_secret_compare:
                for comp in node.comparators:
                    comp_name = get_name(comp).lower() if isinstance(comp, (ast.Name, ast.Attribute)) else ""
                    if any(w in comp_name for w in secret_words):
                        is_secret_compare = True
                        break

            if is_secret_compare and any(isinstance(op, (ast.Eq, ast.NotEq)) for op in node.ops):
                self._add("CR010", node,
                          "Timing-unsafe comparison of secret value",
                          fix="Use hmac.compare_digest() for constant-time comparison")

        self.generic_visit(node)

    def visit_Assign(self, node: ast.Assign) -> None:
        """Detect hardcoded passwords and security-related constants."""
        if "CR014" not in self.ignored:
            for target in node.targets:
                name = get_name(target).lower()
                password_names = {"password", "passwd", "pwd", "pass_word",
                                 "db_password", "db_pass", "mysql_password",
                                 "postgres_password", "redis_password"}
                secret_names = {"secret_key", "api_key", "apikey", "auth_token",
                               "access_token", "private_key", "secret"}

                if any(pw in name for pw in password_names):
                    val = node.value
                    if isinstance(val, ast.Constant) and isinstance(val.value, str) and len(val.value) > 0:
                        # Skip obvious placeholders
                        if val.value.lower() not in ("", "changeme", "xxx", "todo", "none",
                                                      "password", "test", "example"):
                            self._add("CR014", node,
                                      f"Hardcoded password: {name}",
                                      fix="Use environment variables or a secrets manager")

                if any(sk in name for sk in secret_names):
                    val = node.value
                    if isinstance(val, ast.Constant) and isinstance(val.value, str) and len(val.value) > 8:
                        self._add("CR004", node,
                                  f"Hardcoded secret: {name}",
                                  fix="Load from environment variables or secrets manager")

        # CR012: Base64 "encryption"
        if "CR012" not in self.ignored:
            for target in node.targets:
                name = get_name(target).lower()
                if any(w in name for w in ("encrypt", "cipher", "encoded_secret")):
                    if isinstance(node.value, ast.Call):
                        func = get_name(node.value.func)
                        if "b64encode" in func or "base64" in func.lower():
                            self._add("CR012", node,
                                      "Base64 encoding used as encryption",
                                      fix="Base64 is encoding, not encryption. Use Fernet (cryptography) or AES")

        # CR018: assert for security
        if "CR018" not in self.ignored:
            pass  # Handled in visit_Assert

        self.generic_visit(node)

    def visit_Assert(self, node: ast.Assert) -> None:
        """Detect assert used for security checks."""
        if "CR018" not in self.ignored:
            # Check if the assert involves security-related names
            test_text = ast.dump(node.test)
            security_words = ["auth", "permission", "access", "token", "login",
                            "password", "credential", "role", "admin", "verify"]
            if any(w in test_text.lower() for w in security_words):
                self._add("CR018", node,
                          "assert used for security check — disabled with python -O",
                          fix="Use `if not condition: raise PermissionError(...)` instead of assert")

        self.generic_visit(node)

    def visit_Constant(self, node: ast.Constant) -> None:
        """Detect hardcoded byte strings that look like keys."""
        if "CR004" not in self.ignored:
            if isinstance(node.value, bytes) and len(node.value) in (16, 24, 32, 48, 64):
                # Could be a key — check if all bytes are printable ASCII (likely not a key)
                # Heuristic: if it has non-ASCII bytes, more likely a key
                if any(b > 127 or b < 32 for b in node.value):
                    self._add("CR004", node,
                              f"Possible hardcoded key ({len(node.value)} bytes)",
                              fix="Load keys from environment or key management system")

        self.generic_visit(node)

    def _get_parent_context(self, node: ast.AST) -> bool:
        """Heuristic: check if node is used in a security-sensitive context."""
        # Check the source line for security-related variable names
        line = getattr(node, "lineno", 0)
        if 0 < line <= len(self.source_lines):
            src = self.source_lines[line - 1].lower()
            security_words = ["token", "secret", "password", "key", "nonce",
                            "salt", "seed", "session", "csrf", "otp", "pin",
                            "auth", "credential", "api_key"]
            return any(w in src for w in security_words)
        return False

    def check_temp_files(self, tree: ast.AST) -> None:
        """Check for insecure temporary file patterns."""
        if "CR019" in self.ignored:
            return

        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                func = get_name(node.func)
                # Check for open() with /tmp/ path
                if func == "open" and node.args:
                    path_arg = get_string_value(node.args[0])
                    if path_arg and ("/tmp/" in path_arg or path_arg.startswith("tmp")):
                        self._add("CR019", node,
                                  "Hardcoded temp file path — predictable location",
                                  fix="Use tempfile.mkstemp() or tempfile.NamedTemporaryFile()")

                # os.tmpnam, os.tempnam (deprecated)
                if func in ("os.tmpnam", "os.tempnam", "tempfile.mktemp"):
                    self._add("CR019", node,
                              f"{func}() is insecure — race condition vulnerability",
                              fix="Use tempfile.mkstemp() or tempfile.NamedTemporaryFile()")


def analyze_file(file_path: str, source: str, ignored: set[str]) -> list[Finding]:
    """Analyze a single Python file for crypto issues."""
    try:
        tree = ast.parse(source, filename=file_path)
    except SyntaxError:
        return []

    lines = source.split("\n")
    analyzer = CryptoAnalyzer(file_path, lines, ignored)
    analyzer.visit(tree)
    analyzer.check_temp_files(tree)

    return analyzer.findings


# ── Grading ───────────────────────────────────────────────────────────────────

def calculate_grade(findings: list[Finding]) -> tuple[str, int]:
    score = 100
    for f in findings:
        if f.severity == Severity.ERROR:
            score -= 15
        elif f.severity == Severity.WARNING:
            score -= 7
        elif f.severity == Severity.INFO:
            score -= 2
    score = max(0, score)

    if score >= 97:
        return "A+", score
    elif score >= 90:
        return "A", score
    elif score >= 80:
        return "B", score
    elif score >= 70:
        return "C", score
    elif score >= 60:
        return "D", score
    return "F", score


# ── Output ────────────────────────────────────────────────────────────────────

BOLD = "\033[1m"
RESET = "\033[0m"
RED = "\033[91m"
YELLOW = "\033[93m"
GREEN = "\033[92m"
CYAN = "\033[36m"
GRAY = "\033[90m"
DIM = "\033[2m"

SEVERITY_SYMBOLS = {"ERROR": "✖", "WARNING": "▲", "INFO": "ℹ"}
SEVERITY_COLORS = {"ERROR": RED, "WARNING": YELLOW, "INFO": GRAY}


def format_text(findings, grade, score, verbose=False, use_color=True):
    lines = []
    b = BOLD if use_color else ""
    r = RESET if use_color else ""
    dim = DIM if use_color else ""

    lines.append(f"\n{b}cryptaudit{r} — Python Crypto Usage Auditor\n")

    gc = GREEN if score >= 90 else YELLOW if score >= 70 else RED
    if use_color:
        lines.append(f"  Grade: {gc}{b}{grade}{r} ({score}/100)")
    else:
        lines.append(f"  Grade: {grade} ({score}/100)")

    counts = {}
    for f in findings:
        counts[f.severity] = counts.get(f.severity, 0) + 1

    parts = []
    for sev in [Severity.ERROR, Severity.WARNING, Severity.INFO]:
        if sev in counts:
            c = SEVERITY_COLORS[sev] if use_color else ""
            parts.append(f"{c}{counts[sev]} {sev.lower()}{r}" if use_color else f"{counts[sev]} {sev.lower()}")
    lines.append(f"  Findings: {', '.join(parts)}" if parts else "  Findings: none")
    lines.append("")

    if not findings:
        lines.append(f"  {GREEN if use_color else ''}✓ No crypto issues found{r}\n")
        return "\n".join(lines)

    by_file: dict[str, list] = {}
    for f in findings:
        by_file.setdefault(f.file, []).append(f)

    for fp, file_findings in by_file.items():
        lines.append(f"  {b}{fp}{r}")
        for f in sorted(file_findings, key=lambda x: x.line):
            sym = SEVERITY_SYMBOLS.get(f.severity, "●")
            color = SEVERITY_COLORS.get(f.severity, "") if use_color else ""
            lines.append(f"    {color}{sym}{r} [{f.rule_id}] {f.message} :{f.line}")
            if f.context:
                ctx = f.context[:80] + "..." if len(f.context) > 80 else f.context
                lines.append(f"      {dim}→ {ctx}{r}")
            if verbose and f.fix:
                lines.append(f"      {CYAN if use_color else ''}{b}Fix:{r} {f.fix}")
        lines.append("")

    return "\n".join(lines)


def format_json(findings, grade, score):
    return json.dumps({
        "tool": "cryptaudit",
        "version": __version__,
        "grade": grade,
        "score": score,
        "total_findings": len(findings),
        "by_severity": {s: sum(1 for f in findings if f.severity == s)
                        for s in [Severity.ERROR, Severity.WARNING, Severity.INFO]
                        if any(f.severity == s for f in findings)},
        "findings": [f.to_dict() for f in findings],
    }, indent=2)


# ── File Discovery ────────────────────────────────────────────────────────────

SKIP_DIRS = {
    "__pycache__", ".git", ".hg", ".svn", "node_modules",
    ".tox", ".nox", ".mypy_cache", ".pytest_cache",
    ".venv", "venv", "env", ".env", "dist", "build",
    ".eggs", "site-packages",
}


def find_python_files(path: Path) -> list[Path]:
    if path.is_file():
        return [path] if path.suffix == ".py" else []
    files = []
    for root, dirs, fnames in os.walk(path):
        dirs[:] = [d for d in dirs if d not in SKIP_DIRS and not d.startswith(".")]
        for f in sorted(fnames):
            if f.endswith(".py"):
                files.append(Path(root) / f)
    return files


# ── Main ──────────────────────────────────────────────────────────────────────

def list_rules():
    lines = ["\ncryptaudit — Rule Reference\n"]
    for rid in sorted(RULES):
        rule = RULES[rid]
        lines.append(f"  {rid}  [{rule['severity']:7s}]  {rule['name']}: {rule['description']}")
    lines.append("")
    return "\n".join(lines)


def main(argv=None):
    parser = argparse.ArgumentParser(
        prog="cryptaudit",
        description="Python Crypto Usage Auditor — find weak crypto patterns",
    )
    parser.add_argument("path", nargs="?", default=".", help="File or directory")
    parser.add_argument("--json", action="store_true")
    parser.add_argument("--check", nargs="?", const="B", metavar="GRADE")
    parser.add_argument("--verbose", "-v", action="store_true")
    parser.add_argument("--list-rules", action="store_true")
    parser.add_argument("--severity", choices=["ERROR", "WARNING", "INFO"])
    parser.add_argument("--ignore", help="Comma-separated rule IDs to skip")
    parser.add_argument("--no-color", action="store_true")
    parser.add_argument("--version", action="version", version=f"cryptaudit {__version__}")

    args = parser.parse_args(argv)

    if args.list_rules:
        print(list_rules())
        return 0

    target = Path(args.path)
    if not target.exists():
        print(f"Error: {args.path} not found", file=sys.stderr)
        return 2

    ignored = set()
    if args.ignore:
        ignored = {r.strip().upper() for r in args.ignore.split(",")}

    files = find_python_files(target)
    if not files:
        print(f"No Python files found in {args.path}", file=sys.stderr)
        return 2

    all_findings = []
    for fpath in files:
        try:
            source = fpath.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        all_findings.extend(analyze_file(str(fpath), source, ignored))

    if args.severity:
        min_w = Severity.weight(args.severity)
        all_findings = [f for f in all_findings if Severity.weight(f.severity) >= min_w]

    all_findings.sort(key=lambda f: (f.file, f.line))
    grade, score = calculate_grade(all_findings)

    use_color = not args.no_color and sys.stdout.isatty() and not args.json

    if args.json:
        print(format_json(all_findings, grade, score))
    else:
        print(format_text(all_findings, grade, score, verbose=args.verbose, use_color=use_color))

    if args.check:
        threshold = args.check.upper()
        grade_order = {"A+": 6, "A": 5, "B": 4, "C": 3, "D": 2, "F": 1}
        if grade_order.get(grade, 0) < grade_order.get(threshold, 0):
            return 1

    return 0


if __name__ == "__main__":
    sys.exit(main())
