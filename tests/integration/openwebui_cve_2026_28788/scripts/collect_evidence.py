#!/usr/bin/env python3
"""
CVE-2026-28788 Evidence Collection Orchestrator.
Gathers environment details, container manifests, offline simulation proofs,
and live or simulated HTTP traces into a versioned evidence bundle.
Strictly distinguishes offline simulation from live execution.
"""

import argparse
import datetime
import hashlib
import json
import os
import platform
import re
import shutil
import stat
import subprocess
import sys
import tempfile
import unittest
import urllib.request
import urllib.error
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

SCRIPT_DIR = Path(__file__).resolve().parent
LAB_DIR = SCRIPT_DIR.parent
REPO_ROOT = Path(__file__).resolve().parents[4]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))


def get_command_output(cmd: List[str]) -> Tuple[int, str]:
    try:
        res = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, check=False)
        return res.returncode, res.stdout.strip()
    except Exception as e:
        return 1, str(e)


def sha256_file(filepath: Path) -> str:
    h = hashlib.sha256()
    with open(filepath, "rb") as f:
        while chunk := f.read(65536):
            h.update(chunk)
    return h.hexdigest()


def check_docker_daemon(use_sudo: bool = False) -> Dict[str, Any]:
    if not os.path.exists("/var/run/docker.sock"):
        return {
            "accessible": False,
            "details": "Socket /var/run/docker.sock does not exist in current namespace",
            "error_type": "SOCKET_NOT_FOUND",
        }
    cmd = ["sudo", "-n", "docker", "info"] if use_sudo else ["docker", "info"]
    code, out = get_command_output(cmd)
    if code == 0:
        return {"accessible": True, "details": "Docker daemon connected."}
    return {
        "accessible": False,
        "details": out,
        "error_type": "PERMISSION_DENIED" if ("permission denied" in out.lower() or "password is required" in out.lower()) else "SOCKET_UNREACHABLE",
    }


def get_git_info() -> Dict[str, Any]:
    _, branch = get_command_output(["git", "rev-parse", "--abbrev-ref", "HEAD"])
    _, commit = get_command_output(["git", "rev-parse", "HEAD"])
    _, status = get_command_output(["git", "status", "--short"])
    return {
        "branch": branch,
        "commit": commit,
        "dirty_files_count": len([line for line in status.splitlines() if line.strip()]),
    }


def run_offline_simulations() -> Dict[str, Any]:
    suite = unittest.defaultTestLoader.discover(
        str(LAB_DIR / "simulations"), pattern="test_*.py"
    )
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)
    return {
        "tests_run": result.testsRun,
        "was_successful": result.wasSuccessful(),
        "errors": len(result.errors),
        "failures": len(result.failures),
        "skipped": len(result.skipped),
        "details": [
            f"Ran {result.testsRun} simulation tests validating vulnerable, patched, contradictory, "
            f"auth error, and baseline fail-closed states against upstream pinned contracts."
        ],
    }


REQUIRED_RAW_FILES = (
    "firedamp-v085.json",
    "firedamp-v086.json",
    "reproduce-v085.json",
    "reproduce-v086.json",
    "reset-v085.json",
    "final-fixture-verification.json",
)

_EXPECTED_SANITIZED_OUTPUT_FILES = frozenset({
    "sanitized-v085.json",
    "sanitized-v086.json",
    "sanitized-reproduce-v085.json",
    "sanitized-reproduce-v086.json",
    "sanitized-reset-v085.json",
    "sanitized-final-fixture-verification.json",
    "README.md",
    "manifest.json",
})

PINNED_IMAGE_DIGESTS = {
    "v0.8.5": {
        "image": "ghcr.io/open-webui/open-webui:v0.8.5@sha256:6251d208f91373f755c6a42abdbf740d003775dcf2d78b8811a213a822e7350b",
        "manifest_digest": "sha256:6251d208f91373f755c6a42abdbf740d003775dcf2d78b8811a213a822e7350b",
        "status": "vulnerable",
    },
    "v0.8.6": {
        "image": "ghcr.io/open-webui/open-webui:v0.8.6@sha256:4938a90d0b0fb2a7c361a254211704fab72e748c4c7649e5729947fdc56d9dea",
        "manifest_digest": "sha256:4938a90d0b0fb2a7c361a254211704fab72e748c4c7649e5729947fdc56d9dea",
        "status": "patched",
    },
}

FIXTURE_BASELINE = {
    "content_length_bytes": 302,
    "sha256": "b8fe905c936d2f95065012f079a6637825559561b03a52967cf7de42136bf2de",
}


_STRICT_CANARY_RE = re.compile(
    r"^CANARY-FRDP-[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}-[0-9a-fA-F]{4}$"
)
_ANY_CANARY_FRDP_RE = re.compile(r"CANARY-FRDP-[^\s,;\"'`\]\)}<>&|]+")
_BEARER_RE = re.compile(r"(?i)\bbearer\s+[A-Za-z0-9\-._~+/]+=*")
_JWT_RE = re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b")
_SECRET_KEY_CORE_NAMES = (
    r"(?:aws[._-]?)?secret[._-]?access[._-]?key|"
    r"(?:aws[._-]?)?access[._-]?key[._-]?id|"
    r"client[._-]?secret(?:[._-]?value)?|clientsecret(?:value)?|"
    r"secret[._-]?key(?:[._-]?value)?|secretkey(?:value)?|"
    r"private[._-]?key(?:[._-]?value)?|privatekey(?:value)?|"
    r"privkey|"
    r"(?:openai[._-]?)?api[._-]?key(?:[._-]?value)?|(?:openai)?apikey(?:value)?|"
    r"(?:service[._-]?)?access[._-]?token(?:[._-]?value)?|(?:service)?accesstoken(?:value)?|"
    r"refresh[._-]?token(?:[._-]?value)?|refreshtoken(?:value)?|"
    r"auth[._-]?token(?:[._-]?value)?|authtoken(?:value)?|"
    r"session[._-]?token(?:[._-]?value)?|sessiontoken(?:value)?|"
    r"id[._-]?token(?:[._-]?value)?|idtoken(?:value)?|"
    r"bearer[._-]?token(?:[._-]?value)?|bearertoken(?:value)?|"
    r"session[._-]?id|sessionid|"
    r"token[._-]?value|tokenvalue|"
    r"passphrase|pass[._-]?phrase|"
    r"(?:db[._-]?)?password(?:[._-]?value)?|(?:db)?password(?:value)?|passwd|pwd|"
    r"secret(?:[._-]?value)?|"
    r"token"
)
_SECRET_KEY_NAMES = (
    r"(?:[a-zA-Z0-9_.-]+[._-])?(?:" + _SECRET_KEY_CORE_NAMES + r")(?:[._-][a-zA-Z0-9_.-]+)*|"
    r"[a-zA-Z0-9_.-]*(?:password|passwd|pwd|passphrase|secret|privkey|private_?key|api_?key|access_?token|refresh_?token|auth_?token|session_?token|id_?token|bearer_?token|token)[a-zA-Z0-9_.-]*"
)
_QUOTED_SECRET_KEY_NAMES = (
    _SECRET_KEY_NAMES + r"|cookie|set[_-]?cookie|authorization"
)
_SENSITIVE_KEY_NAME_EXACT_RE = re.compile(
    r"^(?:" + _QUOTED_SECRET_KEY_NAMES + r")$",
    re.IGNORECASE,
)

_NON_SENSITIVE_EXACT_KEYS = frozenset({
    "public_key",
    "public_keys",
    "public_key_id",
    "key_id",
    "key_type",
    "key_algorithm",
    "token_count",
    "token_type",
    "max_tokens",
    "total_tokens",
    "prompt_tokens",
    "completion_tokens",
    "jwt_algorithm",
    "algorithm",
    "content_length",
    "sha256",
    "verified_hash",
})

_GENUINE_CREDENTIAL_TERMS = (
    "password",
    "passwd",
    "pwd",
    "passphrase",
    "private_key",
    "privkey",
    "client_secret",
    "secret_key",
    "database_secret",
    "shared_secret",
    "secret_access_key",
    "access_key_id",
    "openai_api_key",
    "api_key",
    "apikey",
    "access_token",
    "refresh_token",
    "auth_token",
    "session_token",
    "id_token",
    "bearer_token",
    "session_id",
    "cookie",
    "set_cookie",
    "authorization",
)


def _normalize_key_name(key: Any) -> str:
    """Normalize camelCase, PascalCase, hyphens, dots, whitespace, slashes, and colons into snake_case."""
    if not isinstance(key, (str, int)):
        return ""
    s = str(key).strip()
    if not s:
        return ""
    s = re.sub(r"([a-z0-9])([A-Z])", r"\1_\2", s)
    s = re.sub(r"([A-Z]+)([A-Z][a-z])", r"\1_\2", s)
    s = re.sub(r"[-.\s/:]+", "_", s.lower())
    return re.sub(r"_+", "_", s).strip("_")


def _is_sensitive_key_name(key: Any) -> bool:
    """
    Check if a key name represents a credential or sensitive property.
    Supports deliberate component-aware normalization (camelCase, PascalCase, dots, hyphens),
    detects genuine credential terms even with qualifiers (e.g. dbPassword, openaiApiKey,
    serviceAccessToken, tokenValue, db_password_value, refreshTokenValue, clientSecretValue,
    DATABASE-PASSWORD, aws.secret.access.key, public_key_password, public_keys_client_secret),
    while preserving legitimate non-sensitive metadata keys (public_key, token_count, max_tokens,
    key_id, jwt_algorithm, sha256).
    Guarantees that genuine credential detection strictly takes precedence over every metadata exemption.
    """
    norm = _normalize_key_name(key)
    if not norm:
        return False

    # 1. Exact non-sensitive metadata keys take precedence when exact
    if norm in _NON_SENSITIVE_EXACT_KEYS:
        return False

    # 2. Genuine credential detection MUST take precedence over every metadata exemption!
    for term in _GENUINE_CREDENTIAL_TERMS:
        if term in norm:
            return True

    parts = set(norm.split("_"))
    if "secret" in parts:
        return True

    if "token" in parts or "tokens" in parts:
        nlp_token_terms = {
            "count", "max", "total", "prompt", "completion",
            "usage", "used", "limit", "remaining", "type", "len", "length", "size"
        }
        if parts & nlp_token_terms:
            return False
        return True

    # 3. Non-sensitive public key metadata exemption (only if NO genuine credential term was matched above)
    if "public_key" in norm or "public_keys" in norm:
        return False

    return bool(_SENSITIVE_KEY_NAME_EXACT_RE.match(str(key).strip()))
_JSON_SECRET_KV_RE = re.compile(
    r'(?i)"(' + _QUOTED_SECRET_KEY_NAMES + r')"\s*:\s*"(?:[^"\\]|\\.)*"'
)
_SINGLE_QUOTED_SECRET_KV_RE = re.compile(
    r"(?i)'(" + _QUOTED_SECRET_KEY_NAMES + r")'\s*:\s*'(?:[^'\\]|\\.)*'"
)
_AUTH_HEADER_RE = re.compile(r"(?i)\b(authorization)\s*[:=]\s*[^\r\n,;]+")
_COOKIE_HEADER_RE = re.compile(r"(?i)\b(set[_-]?cookie|cookie)\s*[:=]\s*[^\r\n]+")
_SECRET_KV_RE = re.compile(
    r"(?i)\b(" + _SECRET_KEY_NAMES + r")\s*[:=]\s*(?:\"(?:[^\"\\]|\\.)*\"|'(?:[^'\\]|\\.)*'|[^\s,;'\"]+)"
)
_SENSITIVE_KEY_PREFIX_RE = re.compile(
    r"(?i)(?:\"(?P<dq_key>" + _QUOTED_SECRET_KEY_NAMES + r")\"\s*(?P<dq_sep>[:=])[ \t]*|"
    r"'(?P<sq_key>" + _QUOTED_SECRET_KEY_NAMES + r")'\s*(?P<sq_sep>[:=])[ \t]*|"
    r"\b(?P<uq_key>" + _SECRET_KEY_NAMES + r")\s*(?P<sep>[:=])[ \t]*)",
)
_FULL_PEM_RE = re.compile(
    r"-----BEGIN (?:[A-Za-z0-9_-]+ )*(?:PRIVATE KEY|KEY|SECRET|CERTIFICATE|PARAMETERS)-----"
    r"[\s\S]*?"
    r"-----END (?:[A-Za-z0-9_-]+ )*(?:PRIVATE KEY|KEY|SECRET|CERTIFICATE|PARAMETERS)-----",
    re.IGNORECASE,
)
_UNCLOSED_PEM_RE = re.compile(
    r"-----BEGIN (?:[A-Za-z0-9_-]+ )*(?:PRIVATE KEY|KEY|SECRET|CERTIFICATE|PARAMETERS)-----"
    r"[\s\S]*?"
    r"(?=(?:\"|'|\r?\n\r?\n|\Z))",
    re.IGNORECASE,
)
_KNOWN_PREFIX_SECRET_RE = re.compile(
    r"\b(?:sk-[A-Za-z0-9_-]{12,}|ghp_[A-Za-z0-9]{12,}|AKIA[0-9A-Z]{16})\b"
)
_UUID_RE = re.compile(r"\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b")
_URL_USERINFO_RE = re.compile(r"(https?://)([^/@\s]+)@")
_YAML_NODE_PROPS_RE = re.compile(
    r"^(?:(?:&[A-Za-z0-9_-]+|!+<[^>\r\n]+>|!+[^ \t\r\n#,]+)[ \t]*)+"
)
_YAML_BLOCK_INDICATOR_RE = re.compile(
    r"^([|>](?:[1-9][\-+]?|[\-+][1-9]?)?)"
)


def _scan_balanced_structure(text: str, start_idx: int) -> Optional[int]:
    """Scan balanced { } or [ ], using a delimiter stack and respecting strings/escapes."""
    first = text[start_idx]
    if first not in ("{", "["):
        return None
    stack = [first]
    in_quote = None
    escaped = False
    i = start_idx + 1
    n = len(text)
    pairs = {"{": "}", "[": "]"}
    while i < n:
        c = text[i]
        if in_quote:
            if escaped:
                escaped = False
            elif c == "\\":
                escaped = True
            elif c == in_quote:
                in_quote = None
        else:
            if c in ('"', "'"):
                in_quote = c
            elif c in ("{", "["):
                stack.append(c)
            elif c in ("}", "]"):
                if not stack or pairs.get(stack[-1]) != c:
                    return None
                stack.pop()
                if not stack:
                    return i + 1
        i += 1
    return None


def _scan_quoted_string(text: str, start_idx: int) -> Optional[int]:
    """Scan a double- or single-quoted string, respecting backslash escapes."""
    quote_char = text[start_idx]
    escaped = False
    i = start_idx + 1
    n = len(text)
    while i < n:
        c = text[i]
        if escaped:
            escaped = False
        elif c == "\\":
            escaped = True
        elif c == quote_char:
            return i + 1
        i += 1
    return None


def _scan_indented_yaml_block(
    text: str,
    start_pos: int,
    key_indent: int,
    key_name: str,
    *,
    has_indicator: bool = False,
    allow_empty: bool = False,
) -> Tuple[int, bool]:
    """
    Scan a multiline YAML block scalar (|, |-, |+, >, >-, >+, |2-, >2+, etc.) or an indented
    sequence / block associated with a sensitive key, determining the block boundary strictly
    via indentation and treating comment-only lines as ignorable when determining boundaries.
    Fails closed (ValueError) if the block indicator or content cannot be safely bounded.
    """
    pos = start_pos
    m_lead = re.match(r"^[ \t]*", text[pos:])
    if m_lead:
        pos += m_lead.end()

    m_props = _YAML_NODE_PROPS_RE.match(text[pos:])
    if m_props:
        pos += m_props.end()

    indicator_found = False
    if has_indicator:
        m_ind = _YAML_BLOCK_INDICATOR_RE.match(text[pos:])
        if m_ind:
            indicator_found = True
            pos += m_ind.end()
            m_rest = re.match(r"^[ \t]*(?:#[^\r\n]*)?", text[pos:])
            if m_rest:
                pos += m_rest.end()

    # If indicator was expected or found, verify rest of line is comment/newline
    if has_indicator or indicator_found:
        if pos < len(text) and text[pos] in ("\r", "\n"):
            if text[pos : pos + 2] == "\r\n":
                pos += 2
            else:
                pos += 1
        elif pos == len(text):
            return pos, True
        else:
            raise ValueError(
                f"Malformed or unbounded YAML block scalar after '{key_name}': unexpected content on indicator line"
            )
    else:
        # No indicator. Check if rest of line is horizontal whitespace and optional comment
        m_rest = re.match(r"^[ \t]*(?:#[^\r\n]*)?", text[pos:])
        if m_rest:
            pos += m_rest.end()
        if pos < len(text) and text[pos] in ("\r", "\n"):
            if text[pos : pos + 2] == "\r\n":
                pos += 2
            else:
                pos += 1
        elif pos == len(text):
            if allow_empty:
                return pos, True
            return start_pos, False
        else:
            return start_pos, False

    last_content_end = pos
    found_any_content = False
    in_quote: Optional[str] = None
    escaped = False

    while pos < len(text):
        line_start = pos
        nl_pos = text.find("\n", pos)
        if nl_pos == -1:
            line_end = len(text)
            next_line_start = len(text)
        else:
            line_end = nl_pos
            if line_end > line_start and text[line_end - 1] == "\r":
                line_end -= 1
            next_line_start = nl_pos + 1

        line_content = text[line_start:line_end]
        stripped = line_content.strip()

        if not stripped:
            pos = next_line_start
            continue

        indent = 0
        for ch in line_content:
            if ch == " ":
                indent += 1
            elif ch == "\t":
                indent = (indent // 8 + 1) * 8
            else:
                break

        # Treat comment-only lines as ignorable while determining boundaries
        if stripped.startswith("#"):
            probe_pos = next_line_start
            has_subsequent_indented = False
            while probe_pos < len(text):
                p_nl = text.find("\n", probe_pos)
                p_end = p_nl if p_nl != -1 else len(text)
                if p_end > probe_pos and text[p_end - 1] == "\r":
                    p_end -= 1
                p_content = text[probe_pos:p_end]
                p_stripped = p_content.strip()
                if p_stripped and not p_stripped.startswith("#"):
                    p_indent = 0
                    for pch in p_content:
                        if pch == " ":
                            p_indent += 1
                        elif pch == "\t":
                            p_indent = (p_indent // 8 + 1) * 8
                        else:
                            break
                    if p_indent > key_indent:
                        has_subsequent_indented = True
                    break
                probe_pos = (p_nl + 1) if p_nl != -1 else len(text)

            if has_subsequent_indented:
                pos = next_line_start
                continue
            else:
                if indent <= key_indent:
                    break
                found_any_content = True
                last_content_end = next_line_start
                pos = next_line_start
                continue

        if indent <= key_indent:
            break

        found_any_content = True
        # For non-block-scalar (e.g. sequence), check for unterminated quotes
        if not (has_indicator or indicator_found):
            for ch in line_content[indent:]:
                if in_quote:
                    if escaped:
                        escaped = False
                    elif ch == "\\":
                        escaped = True
                    elif ch == in_quote:
                        in_quote = None
                else:
                    if ch in ('"', "'"):
                        in_quote = ch

        last_content_end = next_line_start
        pos = next_line_start

    if in_quote is not None:
        raise ValueError(
            f"Malformed or unbounded structured YAML value after '{key_name}': unterminated quote in indented block"
        )

    if not found_any_content and not (has_indicator or indicator_found):
        return start_pos, False

    return last_content_end, True


def _scan_plain_scalar_continuation(
    text: str, start_pos: int, key_indent: int, key_name: str, *, sep: str = ":"
) -> Tuple[int, bool]:
    """
    Scan an unquoted plain scalar value and any subsequent indented scalar continuation lines,
    consuming the complete continuation block including intervening blank and comment-only lines,
    stopping at the same-level sibling key (indent <= key_indent) and preserving it.
    Fails closed (ValueError) if the continuation boundary cannot be safely established.
    """
    if sep == "=":
        # Key=value assignment (e.g. query string, shell, CLI output, markdown table).
        # Scan same-line value up to reliably recognized delimiters:
        # - Markdown table column boundary: [ \t]*\|
        # - Query string parameter boundary: &
        # - Flow mapping/sequence closing: [ \t]*[}\]]
        # - Comma/semicolon before next key/assignment or EOL: [,;][ \t]*(?=[A-Za-z_][A-Za-z0-9_-]*\s*[:=]|\Z)
        # - Space before next key/assignment: [ \t]+(?=[A-Za-z_][A-Za-z0-9_-]*\s*[:=])
        # - Space before CLI flag: [ \t]+(?=--?[A-Za-z0-9])
        nl_pos = text.find("\n", start_pos)
        first_line_end = len(text) if nl_pos == -1 else nl_pos
        if first_line_end > start_pos and text[first_line_end - 1] == "\r":
            first_line_end -= 1
        line_1 = text[start_pos:first_line_end]

        delim_patterns = [
            r"(?<!\\)[ \t]*\|",  # Markdown table pipe (e.g. " | [link]")
            r"&",                 # Query string ampersand (e.g. "&user=alice")
            r"[ \t]*[}\]]",       # Flow closing bracket/brace
            r"[,;][ \t]*(?=[A-Za-z_][A-Za-z0-9_-]*\s*[:=]|[{\[\"']|\Z)",  # Delimiter before next key/structure or EOL
            r"[ \t]+(?=(?:\"(?:" + _QUOTED_SECRET_KEY_NAMES + r")\"|'(?:" + _QUOTED_SECRET_KEY_NAMES + r")'|" + _SECRET_KEY_NAMES + r")\s*[:=])",  # Space before next sensitive key
            r"[ \t]+(?=[A-Za-z_][A-Za-z0-9_-]*\s*=|--?[A-Za-z0-9]|[{\[\"'])",  # Space before next key=value, CLI flag, or structure
        ]
        earliest_delim = len(line_1)
        for pat in delim_patterns:
            m = re.search(pat, line_1)
            if m and m.start() < earliest_delim:
                earliest_delim = m.start()

        val_str = line_1[:earliest_delim].rstrip(" \t")

        # Fail closed on unclosed quotes or unbalanced structures in value
        in_quote_eq: Optional[str] = None
        escaped_eq = False
        stack_eq: List[str] = []
        pairs_eq = {"{": "}", "[": "]"}
        for ch in val_str:
            if in_quote_eq:
                if escaped_eq:
                    escaped_eq = False
                elif ch == "\\":
                    escaped_eq = True
                elif ch == in_quote_eq:
                    in_quote_eq = None
            else:
                if ch in ('"', "'"):
                    in_quote_eq = ch
                elif ch in ("{", "["):
                    stack_eq.append(ch)
                elif ch in ("}", "]"):
                    if not stack_eq or pairs_eq.get(stack_eq[-1]) != ch:
                        raise ValueError(
                            f"Malformed or ambiguous key=value secret value after '{key_name}': unbalanced structure in value"
                        )
                    stack_eq.pop()
        if in_quote_eq is not None:
            raise ValueError(
                f"Malformed or ambiguous key=value secret value after '{key_name}': unclosed quote in value"
            )
        if stack_eq:
            raise ValueError(
                f"Malformed or ambiguous key=value secret value after '{key_name}': unterminated structure in value"
            )

        if earliest_delim == len(line_1) and nl_pos != -1:
            val_end = nl_pos + 1
        else:
            val_end = start_pos + len(val_str)
        return val_end, False

    # YAML key: value mapping
    nl_pos = text.find("\n", start_pos)
    if nl_pos == -1:
        first_line_end = len(text)
        next_line_start = len(text)
    else:
        first_line_end = nl_pos
        if first_line_end > start_pos and text[first_line_end - 1] == "\r":
            first_line_end -= 1
        next_line_start = nl_pos + 1

    line_1 = text[start_pos:first_line_end]

    # Check for inline YAML comment: preceded by whitespace (or start of line)
    m_comment = re.search(r"(?:^|[ \t])#[^\r\n]*$", line_1)
    if m_comment:
        scalar_line_1 = line_1[:m_comment.start()]
    else:
        scalar_line_1 = line_1

    # Check for legitimate comma-delimited sibling mapping key on the same line:
    # Requires a preceding comma or semicolon delimiter, followed by a valid sibling key name,
    # separator (: or =), and non-empty value or closing flow delimiter.
    # An ambiguous colon-space without a preceding delimiter is NOT a sibling boundary.
    m_sibling = re.search(
        r"[,;][ \t]*(?P<sib_key>[A-Za-z_][A-Za-z0-9_-]*|\"[^\"\\]+\"|'[^'\\]+')[ \t]*[:=][ \t]*(?=\S)",
        scalar_line_1,
    )
    if m_sibling:
        sub_text = scalar_line_1[:m_sibling.start()]
        # Verify sub_text does not contain unclosed quotes or unbalanced structures
        if sub_text.count('"') % 2 != 0 or sub_text.count("'") % 2 != 0:
            raise ValueError(
                f"Malformed or ambiguous scalar boundary before sibling key after '{key_name}': unclosed quote"
            )
        stack_sub: List[str] = []
        pairs_sub = {"{": "}", "[": "]"}
        for ch in sub_text:
            if ch in ("{", "["):
                stack_sub.append(ch)
            elif ch in ("}", "]"):
                if not stack_sub or pairs_sub.get(stack_sub[-1]) != ch:
                    raise ValueError(
                        f"Malformed or ambiguous scalar boundary before sibling key after '{key_name}': unbalanced structure"
                    )
                stack_sub.pop()
        if stack_sub:
            raise ValueError(
                f"Malformed or ambiguous scalar boundary before sibling key after '{key_name}': unterminated structure"
            )
        val_end = start_pos + m_sibling.start()
        return val_end, False

    # Check for flow mapping / sequence closing delimiter at end of line 1 (e.g. } or ])
    m_flow_close = re.search(r"[ \t]*[}\]][ \t]*$", scalar_line_1)
    if m_flow_close:
        val_end = start_pos + m_flow_close.start()
        return val_end, False

    # If line 1 has an inline comment, the plain scalar ends before the comment and cannot continue in YAML
    if m_comment:
        val_end = start_pos + len(scalar_line_1.rstrip(" \t"))
        return val_end, False

    # If line 1 reached EOF with no trailing newline
    if nl_pos == -1:
        val_end = start_pos + len(scalar_line_1.rstrip(" \t"))
        return val_end, False

    last_content_end = next_line_start
    has_continuation = False
    in_quote: Optional[str] = None
    escaped = False
    stack: List[str] = []
    pairs = {"{": "}", "[": "]"}

    # Track quote and bracket states across line 1
    for ch in scalar_line_1:
        if in_quote:
            if escaped:
                escaped = False
            elif ch == "\\":
                escaped = True
            elif ch == in_quote:
                in_quote = None
        else:
            if ch in ('"', "'"):
                in_quote = ch
            elif ch in ("{", "["):
                stack.append(ch)
            elif ch in ("}", "]"):
                if not stack or pairs.get(stack[-1]) != ch:
                    raise ValueError(
                        f"Malformed or ambiguous scalar after '{key_name}': unbalanced structure on line 1"
                    )
                stack.pop()

    pos = next_line_start
    while pos < len(text):
        nl = text.find("\n", pos)
        if nl == -1:
            l_end = len(text)
            next_pos = len(text)
        else:
            l_end = nl
            if l_end > pos and text[l_end - 1] == "\r":
                l_end -= 1
            next_pos = nl + 1

        line_content = text[pos:l_end]
        stripped = line_content.strip()

        # Check blank line: intervening if subsequent indented content exists; trailing otherwise
        if not stripped:
            probe = next_pos
            has_subsequent = False
            while probe < len(text):
                p_nl = text.find("\n", probe)
                p_end = p_nl if p_nl != -1 else len(text)
                if p_end > probe and text[p_end - 1] == "\r":
                    p_end -= 1
                p_cont = text[probe:p_end]
                p_strip = p_cont.strip()
                if p_strip and not p_strip.startswith("#"):
                    p_indent = 0
                    for ch in p_cont:
                        if ch == " ":
                            p_indent += 1
                        elif ch == "\t":
                            p_indent = (p_indent // 8 + 1) * 8
                        else:
                            break
                    if p_indent > key_indent:
                        has_subsequent = True
                    break
                probe = (p_nl + 1) if p_nl != -1 else len(text)

            if has_subsequent:
                pos = next_pos
                continue
            else:
                break

        # Check comment-only line: intervening if subsequent indented content exists; trailing otherwise
        if stripped.startswith("#"):
            probe = next_pos
            has_subsequent = False
            while probe < len(text):
                p_nl = text.find("\n", probe)
                p_end = p_nl if p_nl != -1 else len(text)
                if p_end > probe and text[p_end - 1] == "\r":
                    p_end -= 1
                p_cont = text[probe:p_end]
                p_strip = p_cont.strip()
                if p_strip and not p_strip.startswith("#"):
                    p_indent = 0
                    for ch in p_cont:
                        if ch == " ":
                            p_indent += 1
                        elif ch == "\t":
                            p_indent = (p_indent // 8 + 1) * 8
                        else:
                            break
                    if p_indent > key_indent:
                        has_subsequent = True
                    break
                probe = (p_nl + 1) if p_nl != -1 else len(text)

            if has_subsequent:
                pos = next_pos
                continue
            else:
                break

        # Content line: check indentation against key_indent
        indent = 0
        for ch in line_content:
            if ch == " ":
                indent += 1
            elif ch == "\t":
                indent = (indent // 8 + 1) * 8
            else:
                break

        if indent <= key_indent:
            break

        has_continuation = True
        for ch in line_content[indent:]:
            if in_quote:
                if escaped:
                    escaped = False
                elif ch == "\\":
                    escaped = True
                elif ch == in_quote:
                    in_quote = None
            else:
                if ch in ('"', "'"):
                    in_quote = ch
                elif ch in ("{", "["):
                    stack.append(ch)
                elif ch in ("}", "]"):
                    if not stack or pairs.get(stack[-1]) != ch:
                        raise ValueError(
                            f"Malformed or ambiguous scalar continuation after '{key_name}': unbalanced structure in continuation line"
                        )
                    stack.pop()

        last_content_end = next_pos
        pos = next_pos

    if in_quote is not None:
        raise ValueError(
            f"Malformed or ambiguous scalar continuation after '{key_name}': unterminated quote in continuation block"
        )
    if stack:
        raise ValueError(
            f"Malformed or ambiguous scalar continuation after '{key_name}': unterminated structure in continuation block"
        )

    return last_content_end, has_continuation


def _scrub_sensitive_key_values(text: str) -> str:
    """
    Scrub sensitive key-value pairs across JSON objects/arrays, single-quoted dicts,
    and unquoted/YAML key-value pairs, redacting complete structured values (including
    nested objects/arrays, multiline YAML block scalars/sequences, and PEM material)
    and failing closed if a structured value cannot be safely bounded.
    """
    result: List[str] = []
    last_idx = 0
    for m in _SENSITIVE_KEY_PREFIX_RE.finditer(text):
        if m.start() < last_idx:
            continue
        key_dq = m.group("dq_key")
        key_sq = m.group("sq_key")
        key_uq = m.group("uq_key")
        key_name = key_dq or key_sq or key_uq
        if not key_name or not _is_sensitive_key_name(key_name):
            continue
        result.append(text[last_idx:m.start()])
        val_start = m.end()
        sep = m.group("sep") or m.group("dq_sep") or m.group("sq_sep") or ":"

        # Line start and indentation column of the key
        line_start = text.rfind("\n", 0, m.start()) + 1
        key_indent = 0
        for ch in text[line_start:m.start()]:
            if ch == "\t":
                key_indent = (key_indent // 8 + 1) * 8
            else:
                key_indent += 1

        # Check for optional node properties (anchors / tags) after key prefix
        pos = val_start
        m_lead = re.match(r"^[ \t]*", text[pos:])
        if m_lead:
            pos += m_lead.end()

        m_props = _YAML_NODE_PROPS_RE.match(text[pos:])
        if m_props:
            pos += m_props.end()

        # 1. Check for YAML block scalar indicator on the same line
        m_ind = _YAML_BLOCK_INDICATOR_RE.match(text[pos:])
        if m_ind:
            yaml_end, is_yaml = _scan_indented_yaml_block(text, val_start, key_indent, key_name, has_indicator=True)
            if key_dq:
                if yaml_end < len(text) and text[yaml_end - 1] in ("\r", "\n"):
                    result.append(f'"{key_dq}": "[REDACTED_SECRET]"\n')
                else:
                    result.append(f'"{key_dq}": "[REDACTED_SECRET]"')
            elif key_sq:
                if yaml_end < len(text) and text[yaml_end - 1] in ("\r", "\n"):
                    result.append(f"'{key_sq}': '[REDACTED_SECRET]'\n")
                else:
                    result.append(f"'{key_sq}': '[REDACTED_SECRET]'")
            else:
                if yaml_end < len(text) and text[yaml_end - 1] in ("\r", "\n"):
                    result.append(f"{key_uq}=[REDACTED_SECRET]\n")
                else:
                    result.append(f"{key_uq}=[REDACTED_SECRET]")
            last_idx = yaml_end
            continue

        # 2. Check if separator line has only optional comments and newline (multiline block / sequence)
        m_rest = re.match(r"^[ \t]*(?:#[^\r\n]*)?(?:\r?\n|\Z)", text[pos:])
        if m_rest:
            pos_after_rest = pos + m_rest.end()
            m_next_nonws = re.search(r"\S", text[pos_after_rest:])
            if m_next_nonws:
                first_ch = text[pos_after_rest + m_next_nonws.start()]
                if first_ch in ("{", "["):
                    struct_start = pos_after_rest + m_next_nonws.start()
                    val_end = _scan_balanced_structure(text, struct_start)
                    if val_end is None:
                        raise ValueError(f"Malformed or unbounded structured secret value after '{key_name}'")
                    if key_dq:
                        result.append(f'"{key_dq}": "[REDACTED_SECRET]"')
                    elif key_sq:
                        result.append(f"'{key_sq}': '[REDACTED_SECRET]'")
                    else:
                        result.append(f"{key_uq}=[REDACTED_SECRET]")
                    last_idx = val_end
                    continue

            # Check for indented YAML sequence or block (handles comments before/after sequence)
            yaml_end, is_yaml = _scan_indented_yaml_block(text, val_start, key_indent, key_name, has_indicator=False)
            if is_yaml:
                if key_dq:
                    if yaml_end < len(text) and text[yaml_end - 1] in ("\r", "\n"):
                        result.append(f'"{key_dq}": "[REDACTED_SECRET]"\n')
                    else:
                        result.append(f'"{key_dq}": "[REDACTED_SECRET]"')
                elif key_sq:
                    if yaml_end < len(text) and text[yaml_end - 1] in ("\r", "\n"):
                        result.append(f"'{key_sq}': '[REDACTED_SECRET]'\n")
                    else:
                        result.append(f"'{key_sq}': '[REDACTED_SECRET]'")
                else:
                    if yaml_end < len(text) and text[yaml_end - 1] in ("\r", "\n"):
                        result.append(f"{key_uq}=[REDACTED_SECRET]\n")
                    else:
                        result.append(f"{key_uq}=[REDACTED_SECRET]")
                last_idx = yaml_end
                continue

        # 3. Same-line content (after horizontal whitespace and optional props)
        if pos >= len(text):
            if key_dq:
                result.append(f'"{key_dq}": "[REDACTED_SECRET]"')
            elif key_sq:
                result.append(f"'{key_sq}': '[REDACTED_SECRET]'")
            else:
                result.append(f"{key_uq}=[REDACTED_SECRET]")
            last_idx = pos
            continue

        c = text[pos]
        if c in ("{", "["):
            val_end = _scan_balanced_structure(text, pos)
            if val_end is None:
                raise ValueError(f"Malformed or unbounded structured secret value after '{key_name}'")
            if key_dq:
                result.append(f'"{key_dq}": "[REDACTED_SECRET]"')
            elif key_sq:
                result.append(f"'{key_sq}': '[REDACTED_SECRET]'")
            else:
                result.append(f"{key_uq}=[REDACTED_SECRET]")
            last_idx = val_end
        elif c in ('"', "'"):
            val_end = _scan_quoted_string(text, pos)
            if val_end is None:
                raise ValueError(f"Malformed or unbounded quoted secret value after '{key_name}'")
            if key_dq:
                result.append(f'"{key_dq}": "[REDACTED_SECRET]"')
            elif key_sq:
                result.append(f"'{key_sq}': '[REDACTED_SECRET]'")
            else:
                result.append(f"{key_uq}=[REDACTED_SECRET]")
            last_idx = val_end
        else:
            if text[pos:].upper().startswith("-----BEGIN"):
                pem_end = text.upper().find("-----END", pos)
                if pem_end != -1:
                    close_pem = text.find("-----", pem_end + 8)
                    if close_pem != -1:
                        val_end = close_pem + 5
                    else:
                        val_end = len(text)
                else:
                    m_end = re.search(
                        r"(?:\r?\n\s*\r?\n|\r?\n(?=[A-Za-z_][A-Za-z0-9_-]*\s*[:=])|[\"'\]}]|\Z)",
                        text[pos:],
                    )
                    val_end = pos + m_end.start() if m_end else len(text)
            else:
                val_end, is_cont = _scan_plain_scalar_continuation(
                    text, pos, key_indent, key_name, sep=sep
                )

            if key_dq:
                if val_end < len(text) and text[val_end - 1] in ("\r", "\n"):
                    result.append(f'"{key_dq}": "[REDACTED_SECRET]"\n')
                else:
                    result.append(f'"{key_dq}": "[REDACTED_SECRET]"')
            elif key_sq:
                if val_end < len(text) and text[val_end - 1] in ("\r", "\n"):
                    result.append(f"'{key_sq}': '[REDACTED_SECRET]'\n")
                else:
                    result.append(f"'{key_sq}': '[REDACTED_SECRET]'")
            else:
                if val_end < len(text) and text[val_end - 1] in ("\r", "\n"):
                    result.append(f"{key_uq}=[REDACTED_SECRET]\n")
                else:
                    result.append(f"{key_uq}=[REDACTED_SECRET]")
            last_idx = val_end

    result.append(text[last_idx:])
    return "".join(result)


def _sanitize_url(url: Any) -> Any:
    if not isinstance(url, str):
        return url
    return _URL_USERINFO_RE.sub(r"\1", url)


def _normalize_utc_timestamp(value: Any) -> Optional[str]:
    """Validate and normalize an ISO-8601 UTC timestamp, returning None if invalid or non-UTC."""
    if not isinstance(value, str) or not value.strip():
        return None
    raw = value.strip()
    try:
        dt = datetime.datetime.fromisoformat(raw.replace("Z", "+00:00"))
    except ValueError:
        return None
    if dt.tzinfo is None or dt.utcoffset() != datetime.timedelta(0):
        return None
    return dt.astimezone(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _escape_markdown(text: str) -> str:
    """Escape Markdown-special characters and flatten newlines for safe plain-text Markdown rendering."""
    escaped = text.replace("\\", "\\\\")
    for ch in ("`", "*", "_", "{", "}", "[", "]", "(", ")", "#", "|", "<", ">", "!"):
        escaped = escaped.replace(ch, f"\\{ch}")
    return escaped.replace("\r", " ").replace("\n", " ")


def _secure_open_write_0600(target_path: Path | str, *, create_dirs: bool = True) -> int:
    """
    Open/create a file with 0600 permissions using directory-descriptor traversal with
    O_DIRECTORY and O_NOFOLLOW, creating the final file relative to the verified directory
    descriptor to prevent TOCTOU symlink races and directory traversal attacks.
    """
    abs_path = os.path.abspath(os.fspath(target_path))
    parts: List[str] = []
    head = abs_path
    while True:
        head, tail = os.path.split(head)
        if tail:
            parts.append(tail)
        else:
            break
    parts.reverse()
    dir_parts = parts[:-1]
    filename = parts[-1]

    dir_flags = os.O_RDONLY | os.O_DIRECTORY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
    current_fd = os.open("/", dir_flags)
    try:
        for comp in dir_parts:
            try:
                next_fd = os.open(comp, dir_flags, dir_fd=current_fd)
            except FileNotFoundError:
                if create_dirs:
                    os.mkdir(comp, mode=0o700, dir_fd=current_fd)
                    next_fd = os.open(comp, dir_flags, dir_fd=current_fd)
                else:
                    raise
            except OSError as err:
                raise ValueError(
                    f"Refusing to write through symlinked parent directory component: {comp} ({err})"
                ) from err
            os.close(current_fd)
            current_fd = next_fd

        file_flags = (
            os.O_WRONLY
            | os.O_CREAT
            | os.O_TRUNC
            | getattr(os, "O_NOFOLLOW", 0)
            | getattr(os, "O_CLOEXEC", 0)
        )
        try:
            file_fd = os.open(filename, file_flags, 0o600, dir_fd=current_fd)
        except OSError as err:
            raise ValueError(
                f"Refusing to write to pre-existing symlink output path: {filename} ({err})"
            ) from err
        try:
            os.fchmod(file_fd, 0o600)
        except Exception:
            os.close(file_fd)
            raise
        return file_fd
    finally:
        os.close(current_fd)


def _write_secure_output(path: Path, content: str) -> None:
    """Write text to path safely without following symlinks, enforcing 0600 before writing."""
    out_path = Path(os.path.abspath(os.fspath(path)))
    if out_path.is_symlink():
        raise ValueError(f"Refusing to write to pre-existing symlink output path: {out_path}")
    for parent in out_path.parents:
        if parent.is_symlink():
            raise ValueError(f"Refusing to write through symlinked parent directory component: {parent}")
    fd = _secure_open_write_0600(out_path, create_dirs=True)
    with os.fdopen(fd, "w", encoding="utf-8") as handle:
        handle.write(content)


def _sanitize_canary_list(raw_canaries: Any) -> List[str]:
    """Validate canary strings against the synthetic CANARY-FRDP format, redacting malformed values."""
    if not isinstance(raw_canaries, list):
        raise ValueError(f"Expected list for 'leaked_canaries', got {type(raw_canaries).__name__}")
    sanitized: List[str] = []
    for idx, item in enumerate(raw_canaries):
        if not isinstance(item, str):
            raise ValueError(f"Expected string for 'leaked_canaries[{idx}]', got {type(item).__name__}")
        candidate = item.strip()
        if _STRICT_CANARY_RE.match(candidate):
            sanitized.append(candidate)
        else:
            sanitized.append("[REDACTED_MALFORMED_CANARY]")
    return sanitized


def _sanitize_json_node(
    node: Any,
    raw_data: Optional[Dict[str, Any]] = None,
) -> Any:
    """Recursively redact sensitive keys and scrub scalar strings in parsed JSON structures."""
    if isinstance(node, dict):
        res = {}
        for k, v in node.items():
            k_str = str(k).strip()
            if _is_sensitive_key_name(k_str):
                res[k] = "[REDACTED_SECRET]"
            else:
                res[k] = _sanitize_json_node(v, raw_data)
        return res
    elif isinstance(node, list):
        return [_sanitize_json_node(item, raw_data) for item in node]
    elif isinstance(node, str):
        s = node
        if isinstance(raw_data, dict):
            replacements = (
                ("file_id", "TARGET_FILE"),
                ("disposable_file_id", "TARGET_FILE"),
                ("target_file_id", "TARGET_FILE"),
                ("kb_id", "TARGET_KNOWLEDGE_BASE"),
                ("owner_user_id", "VICTIM_USER"),
                ("alice_user_id", "VICTIM_USER"),
                ("bob_user_id", "ATTACKER_USER"),
                ("run_id", "REDACTED_RUN_ID"),
            )
            for key, placeholder in replacements:
                val = raw_data.get(key)
                if isinstance(val, str) and val.strip():
                    s = s.replace(val.strip(), placeholder)
        s = _URL_USERINFO_RE.sub(r"\1", s)
        s = _scrub_sensitive_key_values(s)
        s = _JSON_SECRET_KV_RE.sub(r'"\1": "[REDACTED_SECRET]"', s)
        s = _SINGLE_QUOTED_SECRET_KV_RE.sub(r"'\1': '[REDACTED_SECRET]'", s)
        s = _AUTH_HEADER_RE.sub(r"\1: [REDACTED]", s)
        s = _COOKIE_HEADER_RE.sub(r"\1: [REDACTED_COOKIE]", s)
        s = _BEARER_RE.sub("Bearer [REDACTED_TOKEN]", s)
        s = _JWT_RE.sub("[REDACTED_JWT]", s)
        s = _KNOWN_PREFIX_SECRET_RE.sub("[REDACTED_SECRET]", s)
        s = _SECRET_KV_RE.sub(r"\1=[REDACTED_SECRET]", s)
        s = _FULL_PEM_RE.sub("[REDACTED_SECRET]", s)
        s = _UNCLOSED_PEM_RE.sub("[REDACTED_SECRET]", s)
        s = _UUID_RE.sub("[REDACTED_UUID]", s)
        return s
    else:
        return node


def _sanitize_free_text(
    text: Any,
    raw_data: Optional[Dict[str, Any]] = None,
    *,
    allow_none: bool = False,
    field_name: str = "free_text",
) -> Optional[str]:
    """
    Scrub credentials, Bearer tokens, JWTs, cookies, passwords, URL userinfo, and unintended private UUIDs
    from forwarded free-text fields while preserving valid synthetic CANARY-FRDP-* evidence and redacting
    any malformed CANARY-FRDP-* tokens (including trailing suffixes).
    Fails closed on unexpected non-string types (permitting None only when allow_none=True).
    """
    if text is None:
        if allow_none:
            return None
        raise ValueError(f"Expected string for '{field_name}', got None")
    if not isinstance(text, str):
        raise ValueError(f"Expected string for '{field_name}', got {type(text).__name__}")

    preserved_canaries: List[str] = []

    def _handle_canary(match: re.Match[str]) -> str:
        token = match.group(0)
        if _STRICT_CANARY_RE.match(token):
            preserved_canaries.append(token)
            return f"__FIREDAMP_CANARY_{len(preserved_canaries) - 1}__"
        return "[REDACTED_MALFORMED_CANARY]"

    scrubbed = _ANY_CANARY_FRDP_RE.sub(_handle_canary, text)

    # Where the complete input is valid structured JSON, use structural parsing and recursive redaction
    stripped = scrubbed.strip()
    if stripped.startswith(("{", "[")):
        try:
            parsed_json = json.loads(stripped)
        except (json.JSONDecodeError, UnicodeDecodeError):
            parsed_json = None

        if parsed_json is not None:
            # Separate parsing from sanitization.
            # Only json.loads decoding failures fall through to non-JSON free-text fallback.
            # Any exception raised during recursive sanitization, validation, or redaction
            # MUST propagate and abort publication.
            sanitized_json = _sanitize_json_node(parsed_json, raw_data)
            if "\n" in stripped:
                out_json = json.dumps(sanitized_json, indent=2)
            else:
                out_json = json.dumps(sanitized_json)
            for idx, canary in enumerate(preserved_canaries):
                out_json = out_json.replace(f"__FIREDAMP_CANARY_{idx}__", canary)
            return out_json

    if isinstance(raw_data, dict):
        replacements = (
            ("file_id", "TARGET_FILE"),
            ("disposable_file_id", "TARGET_FILE"),
            ("target_file_id", "TARGET_FILE"),
            ("kb_id", "TARGET_KNOWLEDGE_BASE"),
            ("owner_user_id", "VICTIM_USER"),
            ("alice_user_id", "VICTIM_USER"),
            ("bob_user_id", "ATTACKER_USER"),
            ("run_id", "REDACTED_RUN_ID"),
        )
        for key, placeholder in replacements:
            val = raw_data.get(key)
            if isinstance(val, str) and val.strip():
                scrubbed = scrubbed.replace(val.strip(), placeholder)

    scrubbed = _URL_USERINFO_RE.sub(r"\1", scrubbed)
    scrubbed = _scrub_sensitive_key_values(scrubbed)
    scrubbed = _JSON_SECRET_KV_RE.sub(r'"\1": "[REDACTED_SECRET]"', scrubbed)
    scrubbed = _SINGLE_QUOTED_SECRET_KV_RE.sub(r"'\1': '[REDACTED_SECRET]'", scrubbed)
    scrubbed = _AUTH_HEADER_RE.sub(r"\1: [REDACTED]", scrubbed)
    scrubbed = _COOKIE_HEADER_RE.sub(r"\1: [REDACTED_COOKIE]", scrubbed)
    scrubbed = _BEARER_RE.sub("Bearer [REDACTED_TOKEN]", scrubbed)
    scrubbed = _JWT_RE.sub("[REDACTED_JWT]", scrubbed)
    scrubbed = _KNOWN_PREFIX_SECRET_RE.sub("[REDACTED_SECRET]", scrubbed)
    scrubbed = _SECRET_KV_RE.sub(r"\1=[REDACTED_SECRET]", scrubbed)
    scrubbed = _FULL_PEM_RE.sub("[REDACTED_SECRET]", scrubbed)
    scrubbed = _UNCLOSED_PEM_RE.sub("[REDACTED_SECRET]", scrubbed)
    scrubbed = _UUID_RE.sub("[REDACTED_UUID]", scrubbed)

    for idx, canary in enumerate(preserved_canaries):
        scrubbed = scrubbed.replace(f"__FIREDAMP_CANARY_{idx}__", canary)
    return scrubbed


def sanitize_firedamp_report(raw_data: Dict[str, Any], version: str) -> Dict[str, Any]:
    """
    Sanitizes Firedamp probe results:
    - Normalizes internal run ID to role-based run identifier
    - Replaces internal target_file_id with TARGET_FILE
    - Scrubs credentials/tokens/unintended UUIDs from target_response while preserving valid CANARY-FRDP tokens
    - Validates leaked_canaries against CANARY-FRDP format, redacting malformed entries
    """
    return {
        "cve_id": raw_data.get("cve_id", "CVE-2026-28788"),
        "run_id": f"firedamp-lab-run-{version}",
        "target_url": _sanitize_url(raw_data.get("target_url")),
        "target_file_id": "TARGET_FILE",
        "severity": raw_data.get("severity"),
        "target_response": _sanitize_free_text(
            raw_data.get("target_response"), raw_data, allow_none=False, field_name="target_response"
        ),
        "leaked_canaries": _sanitize_canary_list(raw_data.get("leaked_canaries", [])),
        "is_vulnerable": bool(raw_data.get("is_vulnerable")),
        "is_clean": bool(raw_data.get("is_clean")),
        "is_inconclusive": bool(raw_data.get("is_inconclusive")),
    }


def sanitize_reproduce_report(raw_data: Dict[str, Any], version: str) -> Dict[str, Any]:
    """
    Sanitizes direct reproduction report:
    - Replaces internal user UUIDs with VICTIM_USER and ATTACKER_USER
    - Replaces internal KB UUID with TARGET_KNOWLEDGE_BASE
    - Replaces internal file UUID with TARGET_FILE across root and batch_response items
    - Strictly validates and scrubs free-text reason, tracer_marker, and batch error fields
    - Preserves exact verdicts, HTTP status, baseline & post-readback hashes
    """
    batch_resp = raw_data.get("batch_response", {})
    sanitized_results = []
    for item in batch_resp.get("results", []):
        sanitized_results.append({
            "file_id": "TARGET_FILE",
            "status": item.get("status"),
            "error": _sanitize_free_text(
                item.get("error"), raw_data, allow_none=True, field_name="batch_response.results[].error"
            ),
        })
    sanitized_errors = []
    for item in batch_resp.get("errors", []):
        sanitized_errors.append({
            "file_id": "TARGET_FILE",
            "status": item.get("status"),
            "error": _sanitize_free_text(
                item.get("error"), raw_data, allow_none=False, field_name="batch_response.errors[].error"
            ),
        })

    return {
        "verdict": raw_data.get("verdict"),
        "reason": _sanitize_free_text(
            raw_data.get("reason"), raw_data, allow_none=False, field_name="reason"
        ),
        "target_url": _sanitize_url(raw_data.get("target_url")),
        "disposable_file_id": "TARGET_FILE",
        "kb_id": "TARGET_KNOWLEDGE_BASE",
        "alice_user_id": "VICTIM_USER",
        "bob_user_id": "ATTACKER_USER",
        "tracer_marker": _sanitize_free_text(
            raw_data.get("tracer_marker"), raw_data, allow_none=False, field_name="tracer_marker"
        ),
        "tracer_found_in_readback": bool(raw_data.get("tracer_found_in_readback")),
        "http_status": raw_data.get("http_status"),
        "batch_response": {
            "results": sanitized_results,
            "errors": sanitized_errors,
        },
        "baseline_sha256": raw_data.get("baseline_sha256"),
        "post_readback_sha256": raw_data.get("post_readback_sha256"),
    }


def sanitize_reset_report(raw_data: Dict[str, Any]) -> Dict[str, Any]:
    """
    Sanitizes fixture reset verification output:
    - Replaces internal file, KB, and owner UUIDs with role-based placeholders if present
    - Never forwards tokens or credentials
    - Preserves exact restoration status, baseline hash, content length, neighboring count,
      and non-exhaustive vector cleanup diagnostics
    """
    sanitized: Dict[str, Any] = {
        "status": raw_data["status"],
        "target_version": raw_data["target_version"],
        "content_length": raw_data["content_length"],
        "sha256": raw_data["sha256"],
        "verified_owner": raw_data["verified_owner"],
        "verified_hash": raw_data["verified_hash"],
        "verified_kb_membership": raw_data["verified_kb_membership"],
        "preserved_other_file_count": raw_data["preserved_other_file_count"],
        "vector_removal_request_accepted": raw_data["vector_removal_request_accepted"],
        "vector_cleanup_verification": raw_data["vector_cleanup_verification"],
        "verified_vector_cleanup": raw_data["verified_vector_cleanup"],
    }
    if "file_id" in raw_data:
        sanitized["file_id"] = "TARGET_FILE"
    if "kb_id" in raw_data:
        sanitized["kb_id"] = "TARGET_KNOWLEDGE_BASE"
    if "owner_user_id" in raw_data:
        sanitized["owner_user_id"] = "VICTIM_USER"

    if "vector_cleanup_note" in raw_data and raw_data["vector_cleanup_note"] is not None:
        note = _sanitize_free_text(
            raw_data["vector_cleanup_note"], raw_data, allow_none=False, field_name="reset.vector_cleanup_note"
        )
        if note and note.strip():
            sanitized["vector_cleanup_note"] = note

    return sanitized


def sanitize_final_verification_report(raw_data: Dict[str, Any]) -> Dict[str, Any]:
    """
    Sanitizes final independent read-only fixture verification output:
    - Keeps only facts supported by the source artifact without synthesizing absent placeholder fields
    - Pseudonymizes resource/user UUIDs only when present in source target entries
    - Scrubs credentials/tokens/unintended UUIDs from vector_cleanup_note
    """
    raw_targets = raw_data.get("targets", {})
    sanitized_targets: Dict[str, Any] = {}
    for key in ("v0.8.5", "v0.8.6"):
        t = raw_targets[key]
        entry: Dict[str, Any] = {
            "expected_version": t["expected_version"],
            "verified_version": t["verified_version"],
            "target_url": _sanitize_url(t["target_url"]),
            "baseline_verified": t["baseline_verified"],
            "original_sha256": t["original_sha256"],
            "content_length": t["content_length"],
            "target_in_alice_kb": t["target_in_alice_kb"],
            "kb_file_count": t["kb_file_count"],
            "identities_and_read_metadata_verified": t["identities_and_read_metadata_verified"],
        }
        if "target_file_id" in t or "file_id" in t:
            entry["target_file_id"] = "TARGET_FILE"
        if "kb_id" in t:
            entry["kb_id"] = "TARGET_KNOWLEDGE_BASE"
        if "alice_user_id" in t:
            entry["alice_user_id"] = "VICTIM_USER"
        if "bob_user_id" in t:
            entry["bob_user_id"] = "ATTACKER_USER"
        sanitized_targets[key] = entry

    raw_note = raw_data.get("vector_cleanup_note")
    if raw_note is None or (isinstance(raw_note, str) and not raw_note.strip()):
        note = (
            "Independent read-only fixture verification checks server version, identities, "
            "ownership, KB membership, and indexed content baseline only; exhaustive vector "
            "cleanup is not verified."
        )
    else:
        note = _sanitize_free_text(raw_note, allow_none=False, field_name="final_verification.vector_cleanup_note") or ""
        for key in ("v0.8.5", "v0.8.6"):
            if key in raw_targets and isinstance(raw_targets[key], dict):
                note = _sanitize_free_text(
                    note, raw_targets[key], allow_none=False, field_name="final_verification.vector_cleanup_note"
                ) or ""

    sanitized: Dict[str, Any] = {
        "verification_mode": raw_data["verification_mode"],
        "live_execution": raw_data["live_execution"],
        "read_only": raw_data["read_only"],
        "vector_cleanup_verified": raw_data["vector_cleanup_verified"],
        "vector_cleanup_note": note,
        "targets": sanitized_targets,
    }
    normalized_verified_at = _normalize_utc_timestamp(raw_data.get("verified_at_utc"))
    if normalized_verified_at is not None:
        sanitized["verified_at_utc"] = normalized_verified_at
    return sanitized


def is_valid_sha256(val: Any) -> bool:
    return isinstance(val, str) and len(val) == 64 and all(c in "0123456789abcdef" for c in val.lower())


def validate_raw_reports(
    firedamp_v085: Dict[str, Any],
    firedamp_v086: Dict[str, Any],
    reproduce_v085: Dict[str, Any],
    reproduce_v086: Dict[str, Any],
    reset_v085: Dict[str, Any],
    final_verification: Dict[str, Any],
) -> None:
    """
    Validates that the 6 raw reports represent genuine, consistent, differential,
    and truthfully bounded evidence for CVE-2026-28788 across vulnerable (v0.8.5)
    and patched (v0.8.6) targets.
    Fails closed (raises ValueError) if any precondition, verdict, hash, strict type,
    reset status, final verification fact, or differential contrast is invalid or contradictory.
    """
    # 1. Type and presence checks
    for name, data in [
        ("firedamp-v085", firedamp_v085),
        ("firedamp-v086", firedamp_v086),
        ("reproduce-v085", reproduce_v085),
        ("reproduce-v086", reproduce_v086),
        ("reset-v085", reset_v085),
        ("final-fixture-verification", final_verification),
    ]:
        if not isinstance(data, dict) or not data:
            raise ValueError(f"Raw report '{name}' is empty or not a valid JSON object")

    # 2. Strict CVE ID validation
    for name, data in [("firedamp-v085", firedamp_v085), ("firedamp-v086", firedamp_v086)]:
        cve_id = data.get("cve_id")
        if not isinstance(cve_id, str) or cve_id != "CVE-2026-28788":
            raise ValueError(f"{name} cve_id must be string 'CVE-2026-28788', got {cve_id!r}")

    # 3. Target URL checks and cross-validation
    expected_v085_url = "http://127.0.0.1:13085"
    expected_v086_url = "http://127.0.0.1:13086"

    for name, data in [("firedamp-v085", firedamp_v085), ("reproduce-v085", reproduce_v085)]:
        url = data.get("target_url")
        if not isinstance(url, str) or url != expected_v085_url:
            raise ValueError(f"{name} target_url must be string '{expected_v085_url}', got {url!r}")

    for name, data in [("firedamp-v086", firedamp_v086), ("reproduce-v086", reproduce_v086)]:
        url = data.get("target_url")
        if not isinstance(url, str) or url != expected_v086_url:
            raise ValueError(f"{name} target_url must be string '{expected_v086_url}', got {url!r}")

    # 4. v0.8.5 Firedamp Probe Validation (Vulnerable Target)
    sev_v085 = firedamp_v085.get("severity")
    if not isinstance(sev_v085, str) or sev_v085 not in ("direct_leak", "critical"):
        raise ValueError(f"firedamp-v085 severity must be string 'direct_leak' or 'critical', got {sev_v085!r}")

    is_vuln_v085 = firedamp_v085.get("is_vulnerable")
    is_clean_v085 = firedamp_v085.get("is_clean")
    is_inconc_v085 = firedamp_v085.get("is_inconclusive")
    if type(is_vuln_v085) is not bool or not is_vuln_v085:
        raise ValueError(f"firedamp-v085 is_vulnerable must be True, got {is_vuln_v085!r}")
    if type(is_clean_v085) is not bool or is_clean_v085:
        raise ValueError(f"firedamp-v085 is_clean must be False, got {is_clean_v085!r}")
    if type(is_inconc_v085) is not bool or is_inconc_v085:
        raise ValueError(f"firedamp-v085 is_inconclusive must be False, got {is_inconc_v085!r}")

    canaries_v085 = firedamp_v085.get("leaked_canaries")
    if not isinstance(canaries_v085, list) or len(canaries_v085) == 0 or not all(isinstance(c, str) and c for c in canaries_v085):
        raise ValueError(
            f"firedamp-v085 leaked_canaries must be a non-empty list of strings, got count={len(canaries_v085) if isinstance(canaries_v085, list) else type(canaries_v085).__name__}"
        )

    resp_v085 = firedamp_v085.get("target_response")
    if not isinstance(resp_v085, str) or ("COMPROMISED" not in resp_v085 and not any(c in resp_v085 for c in canaries_v085)):
        raise ValueError("firedamp-v085 target_response must be a string containing 'COMPROMISED' or leaked canary")

    # 5. v0.8.6 Firedamp Probe Validation (Patched Target)
    sev_v086 = firedamp_v086.get("severity")
    if not isinstance(sev_v086, str) or sev_v086 != "none":
        raise ValueError(f"firedamp-v086 severity must be string 'none', got {sev_v086!r}")

    is_vuln_v086 = firedamp_v086.get("is_vulnerable")
    is_clean_v086 = firedamp_v086.get("is_clean")
    is_inconc_v086 = firedamp_v086.get("is_inconclusive")
    if type(is_vuln_v086) is not bool or is_vuln_v086:
        raise ValueError(f"firedamp-v086 is_vulnerable must be False, got {is_vuln_v086!r}")
    if type(is_clean_v086) is not bool or not is_clean_v086:
        raise ValueError(f"firedamp-v086 is_clean must be True, got {is_clean_v086!r}")
    if type(is_inconc_v086) is not bool or is_inconc_v086:
        raise ValueError(f"firedamp-v086 is_inconclusive must be False, got {is_inconc_v086!r}")

    canaries_v086 = firedamp_v086.get("leaked_canaries")
    if not isinstance(canaries_v086, list) or len(canaries_v086) != 0:
        raise ValueError(f"firedamp-v086 leaked_canaries must be an empty list, got count={len(canaries_v086)}")

    resp_v086 = firedamp_v086.get("target_response")
    if not isinstance(resp_v086, str):
        raise ValueError(f"firedamp-v086 target_response must be a string, got {type(resp_v086).__name__}")
    resp_v086_lower = resp_v086.lower()
    if "clean" not in resp_v086_lower:
        raise ValueError("firedamp-v086 target_response must indicate CLEAN state")
    if not ("permission denied" in resp_v086_lower or "not file owner" in resp_v086_lower):
        raise ValueError("firedamp-v086 target_response must report file ownership authorization rejection")

    # 6. v0.8.5 Direct Reproduction Validation (Vulnerable Target)
    verdict_v085 = reproduce_v085.get("verdict")
    if not isinstance(verdict_v085, str) or verdict_v085 != "VULNERABLE_CONFIRMED":
        raise ValueError(f"reproduce-v085 verdict must be 'VULNERABLE_CONFIRMED', got {verdict_v085!r}")

    tracer_v085 = reproduce_v085.get("tracer_found_in_readback")
    if type(tracer_v085) is not bool or not tracer_v085:
        raise ValueError(f"reproduce-v085 tracer_found_in_readback must be True, got {tracer_v085!r}")

    http_v085 = reproduce_v085.get("http_status")
    if type(http_v085) is not int or http_v085 != 200:
        raise ValueError(f"reproduce-v085 http_status must be integer 200, got {http_v085!r}")

    base_sha_v085 = reproduce_v085.get("baseline_sha256")
    if not is_valid_sha256(base_sha_v085) or base_sha_v085 != FIXTURE_BASELINE["sha256"]:
        raise ValueError(f"reproduce-v085 baseline_sha256 must match {FIXTURE_BASELINE['sha256']}, got {base_sha_v085!r}")

    post_sha_v085 = reproduce_v085.get("post_readback_sha256")
    if not is_valid_sha256(post_sha_v085) or post_sha_v085 == base_sha_v085:
        raise ValueError(f"reproduce-v085 post_readback_sha256 must be valid SHA-256 differing from baseline, got {post_sha_v085!r}")

    batch_resp_v085 = reproduce_v085.get("batch_response")
    if not isinstance(batch_resp_v085, dict):
        raise ValueError(f"reproduce-v085 batch_response must be a dictionary, got {type(batch_resp_v085)}")
    results_v085 = batch_resp_v085.get("results")
    if not isinstance(results_v085, list) or len(results_v085) == 0:
        raise ValueError("reproduce-v085 batch_response.results must be a non-empty list")
    for r in results_v085:
        if not isinstance(r, dict) or r.get("status") != "completed":
            raise ValueError(f"reproduce-v085 batch_response result item must be dict with status='completed', got {type(r).__name__}")

    # 7. v0.8.6 Direct Reproduction Validation (Patched Target)
    verdict_v086 = reproduce_v086.get("verdict")
    if not isinstance(verdict_v086, str) or verdict_v086 != "PATCHED_CONFIRMED":
        raise ValueError(f"reproduce-v086 verdict must be 'PATCHED_CONFIRMED', got {verdict_v086!r}")

    tracer_v086 = reproduce_v086.get("tracer_found_in_readback")
    if type(tracer_v086) is not bool or tracer_v086:
        raise ValueError(f"reproduce-v086 tracer_found_in_readback must be False, got {tracer_v086!r}")

    http_v086 = reproduce_v086.get("http_status")
    if type(http_v086) is not int or http_v086 != 200:
        raise ValueError(f"reproduce-v086 http_status must be integer 200, got {http_v086!r}")

    base_sha_v086 = reproduce_v086.get("baseline_sha256")
    if not is_valid_sha256(base_sha_v086) or base_sha_v086 != FIXTURE_BASELINE["sha256"]:
        raise ValueError(f"reproduce-v086 baseline_sha256 must match {FIXTURE_BASELINE['sha256']}, got {base_sha_v086!r}")

    post_sha_v086 = reproduce_v086.get("post_readback_sha256")
    if not is_valid_sha256(post_sha_v086) or post_sha_v086 != base_sha_v086:
        raise ValueError(f"reproduce-v086 post_readback_sha256 must match baseline ({base_sha_v086}), got {post_sha_v086!r}")

    batch_resp_v086 = reproduce_v086.get("batch_response")
    if not isinstance(batch_resp_v086, dict):
        raise ValueError(f"reproduce-v086 batch_response must be a dictionary, got {type(batch_resp_v086)}")
    errors_v086 = batch_resp_v086.get("errors")
    if not isinstance(errors_v086, list) or len(errors_v086) == 0:
        raise ValueError("reproduce-v086 batch_response.errors must be a non-empty list reporting authorization rejection")
    ownership_rejected = False
    for err in errors_v086:
        if not isinstance(err, dict):
            raise ValueError(f"reproduce-v086 batch_response.errors item must be a dict, got {type(err).__name__}")
        if err.get("status") != "failed":
            raise ValueError(
                f"reproduce-v086 batch_response.errors item status must be 'failed', got {type(err.get('status')).__name__}"
            )
        err_msg = str(err.get("error", "")).lower()
        if "permission denied" in err_msg or "not file owner" in err_msg:
            ownership_rejected = True
    if not ownership_rejected:
        raise ValueError("reproduce-v086 batch_response.errors must contain per-file ownership rejection ('Permission denied: not file owner')")

    # 8. v0.8.5 Fixture Reset Verification Validation
    reset_ver = reset_v085.get("target_version")
    if not isinstance(reset_ver, str) or reset_ver != "0.8.5":
        raise ValueError(f"reset-v085 target_version must be '0.8.5', got {reset_ver!r}")

    reset_status = reset_v085.get("status")
    expected_reset_status = "RESTORED_CONTENT_AND_MEMBERSHIP_VECTOR_UNVERIFIED"
    if not isinstance(reset_status, str) or reset_status != expected_reset_status:
        raise ValueError(
            f"reset-v085 status must be '{expected_reset_status}', got {reset_status!r}"
        )

    reset_sha = reset_v085.get("sha256")
    if not is_valid_sha256(reset_sha) or reset_sha != FIXTURE_BASELINE["sha256"]:
        raise ValueError(
            f"reset-v085 sha256 must match baseline ({FIXTURE_BASELINE['sha256']}), got {reset_sha!r}"
        )

    reset_len = reset_v085.get("content_length")
    if type(reset_len) is not int or reset_len != FIXTURE_BASELINE["content_length_bytes"]:
        raise ValueError(
            f"reset-v085 content_length must be integer {FIXTURE_BASELINE['content_length_bytes']}, got {reset_len!r}"
        )

    for bool_field in (
        "verified_owner",
        "verified_hash",
        "verified_kb_membership",
        "vector_removal_request_accepted",
    ):
        val = reset_v085.get(bool_field)
        if type(val) is not bool or not val:
            raise ValueError(f"reset-v085 {bool_field} must be boolean True, got {val!r}")

    preserved_count = reset_v085.get("preserved_other_file_count")
    if type(preserved_count) is not int or preserved_count < 0:
        raise ValueError(
            f"reset-v085 preserved_other_file_count must be a non-negative integer, got {preserved_count!r}"
        )

    vec_diag = reset_v085.get("vector_cleanup_verification")
    if not isinstance(vec_diag, str) or vec_diag != "NO_MARKER_IN_TOP_K_NOT_EXHAUSTIVE":
        raise ValueError(
            "reset-v085 vector_cleanup_verification must be 'NO_MARKER_IN_TOP_K_NOT_EXHAUSTIVE', "
            f"got {vec_diag!r}"
        )

    vec_verified = reset_v085.get("verified_vector_cleanup")
    if type(vec_verified) is not bool or vec_verified is not False:
        raise ValueError(
            f"reset-v085 verified_vector_cleanup must be boolean False, got {vec_verified!r}"
        )

    # 9. Final Independent Read-Only Fixture Verification Validation
    verif_mode = final_verification.get("verification_mode")
    if not isinstance(verif_mode, str) or verif_mode != "live_read_only_verification":
        raise ValueError(
            f"final-fixture-verification verification_mode must be 'live_read_only_verification', got {verif_mode!r}"
        )

    live_exec = final_verification.get("live_execution")
    if type(live_exec) is not bool or not live_exec:
        raise ValueError(f"final-fixture-verification live_execution must be boolean True, got {live_exec!r}")

    read_only_flag = final_verification.get("read_only")
    if type(read_only_flag) is not bool or not read_only_flag:
        raise ValueError(f"final-fixture-verification read_only must be boolean True, got {read_only_flag!r}")

    final_vec_verified = final_verification.get("vector_cleanup_verified")
    if type(final_vec_verified) is not bool or final_vec_verified is not False:
        raise ValueError(
            f"final-fixture-verification vector_cleanup_verified must be boolean False, got {final_vec_verified!r}"
        )

    targets = final_verification.get("targets")
    if not isinstance(targets, dict):
        raise ValueError("final-fixture-verification targets must be a dictionary")

    for target_key, exp_ver, exp_url in (
        ("v0.8.5", "0.8.5", expected_v085_url),
        ("v0.8.6", "0.8.6", expected_v086_url),
    ):
        t_entry = targets.get(target_key)
        if not isinstance(t_entry, dict):
            raise ValueError(f"final-fixture-verification targets['{target_key}'] must be a dictionary")

        exp_v = t_entry.get("expected_version")
        ver_v = t_entry.get("verified_version")
        if not isinstance(exp_v, str) or exp_v != exp_ver:
            raise ValueError(
                f"final-fixture-verification targets['{target_key}'].expected_version must be '{exp_ver}', got {exp_v!r}"
            )
        if not isinstance(ver_v, str) or ver_v != exp_ver:
            raise ValueError(
                f"final-fixture-verification targets['{target_key}'].verified_version must be '{exp_ver}', got {ver_v!r}"
            )

        t_url = t_entry.get("target_url")
        if not isinstance(t_url, str) or t_url != exp_url:
            raise ValueError(
                f"final-fixture-verification targets['{target_key}'].target_url must be '{exp_url}', got {t_url!r}"
            )

        for bool_field in (
            "baseline_verified",
            "target_in_alice_kb",
            "identities_and_read_metadata_verified",
        ):
            bval = t_entry.get(bool_field)
            if type(bval) is not bool or not bval:
                raise ValueError(
                    f"final-fixture-verification targets['{target_key}'].{bool_field} must be boolean True, got {bval!r}"
                )

        kb_count = t_entry.get("kb_file_count")
        if type(kb_count) is not int or kb_count < 1:
            raise ValueError(
                f"final-fixture-verification targets['{target_key}'].kb_file_count must be a positive integer, got {kb_count!r}"
            )

        t_sha = t_entry.get("original_sha256")
        if not is_valid_sha256(t_sha) or t_sha != FIXTURE_BASELINE["sha256"]:
            raise ValueError(
                f"final-fixture-verification targets['{target_key}'].original_sha256 must match baseline ({FIXTURE_BASELINE['sha256']}), got {t_sha!r}"
            )

        t_len = t_entry.get("content_length")
        if type(t_len) is not int or t_len != FIXTURE_BASELINE["content_length_bytes"]:
            raise ValueError(
                f"final-fixture-verification targets['{target_key}'].content_length must be integer {FIXTURE_BASELINE['content_length_bytes']}, got {t_len!r}"
            )

    expected_v085_kb_count = 1 + preserved_count
    actual_v085_kb_count = targets["v0.8.5"]["kb_file_count"]
    if actual_v085_kb_count != expected_v085_kb_count:
        raise ValueError(
            f"Cross-artifact count mismatch: final-fixture-verification targets['v0.8.5'].kb_file_count "
            f"({actual_v085_kb_count}) must equal 1 + reset-v085.preserved_other_file_count ({expected_v085_kb_count})"
        )


def generate_bundle_readme(
    firedamp_v085: Dict[str, Any],
    firedamp_v086: Dict[str, Any],
    reproduce_v085: Dict[str, Any],
    reproduce_v086: Dict[str, Any],
    reset_v085: Dict[str, Any],
    final_verification: Dict[str, Any],
) -> str:
    """Generates the authoritative README.md for the sanitized evidence bundle."""
    v085_post_sha = reproduce_v085["post_readback_sha256"]
    v086_post_sha = reproduce_v086["post_readback_sha256"]
    v085_http_status = f"{reproduce_v085['http_status']} OK"
    v086_http_status = f"{reproduce_v086['http_status']} OK"

    v085_canaries = _sanitize_canary_list(firedamp_v085.get("leaked_canaries", []))
    v085_canaries_display = (
        ", ".join(
            f"`{c}`" if _STRICT_CANARY_RE.match(c) else _escape_markdown(c)
            for c in v085_canaries
        )
        if v085_canaries
        else "None"
    )
    v086_canaries = _sanitize_canary_list(firedamp_v086.get("leaked_canaries", []))
    v086_canaries_display = (
        ", ".join(
            f"`{c}`" if _STRICT_CANARY_RE.match(c) else _escape_markdown(c)
            for c in v086_canaries
        )
        if v086_canaries
        else "None (Zero leaks detected)"
    )

    v085_status_raw = reproduce_v085["batch_response"]["results"][0].get("status", "completed")
    v085_status = _escape_markdown(
        _sanitize_free_text(v085_status_raw, reproduce_v085, allow_none=False, field_name="batch_response.results[0].status") or ""
    )
    v086_err_raw = reproduce_v086["batch_response"]["errors"][0].get("error", "Permission denied: not file owner")
    v086_err_sanitized = (
        _sanitize_free_text(v086_err_raw, reproduce_v086, allow_none=False, field_name="batch_response.errors[0].error") or ""
    )
    v086_err_msg = _escape_markdown(v086_err_sanitized)

    preserved_count = reset_v085["preserved_other_file_count"]
    if preserved_count == 0:
        neighbor_line = (
            "0 other files were present in the disposable knowledge base during the actual live reset "
            "(no neighboring files were present to preserve)."
        )
    else:
        neighbor_line = (
            f"Reset reported `preserved_other_file_count={preserved_count}` and final KB membership count "
            f"matched ({1 + preserved_count} total files in KB); individual neighboring file contents and "
            "identities are not separately hashed or recorded in the reset artifact."
        )

    fv_085 = final_verification["targets"]["v0.8.5"]
    fv_086 = final_verification["targets"]["v0.8.6"]
    fv_085_sha_match = "Matches" if fv_085["original_sha256"] == FIXTURE_BASELINE["sha256"] else "Mismatch"
    fv_086_sha_match = "Matches" if fv_086["original_sha256"] == FIXTURE_BASELINE["sha256"] else "Mismatch"

    return f"""# CVE-2026-28788 Evidence Bundle: Differential Validation

## 1. Vulnerability & Affected Endpoint

- **Vulnerability ID:** CVE-2026-28788
- **Advisory:** GHSA-jjp7-g2jw-wh3j
- **Affected Product:** Open WebUI < 0.8.6 (Fixed in v0.8.6)
- **Bug Class:** Write-Side Access & Poisoning (`write_side_access_poisoning`)
- **Vulnerable Endpoint:** `POST /api/v1/retrieval/process/files/batch`
- **Root Cause Mechanism:** The batch processing endpoint iterated through user-supplied `files` models and updated indexed file content (`File.data.content`) and vector database embeddings without validating whether the requesting user owned each file. Any authenticated user with access to a shared knowledge base could submit another user's file UUID and overwrite its indexed content.

---

## 2. Test Objective & Authorization Preconditions

### Objective
Verify that an authenticated non-owner with read-only access to a shared knowledge base cannot mutate the underlying content of another user's file via the batch-processing endpoint.

### Preconditions & Setup
1. **Victim Tenant (Alice):** Owns a disposable text file and a shared knowledge base.
2. **Attacker Tenant (Bob):** Authenticated user with read-only access to Alice's knowledge base.
3. **Target Instances:**
   - Vulnerable Target: Open WebUI v0.8.5 (`http://127.0.0.1:13085`)
   - Patched Target: Open WebUI v0.8.6 (`http://127.0.0.1:13086`)
4. **Verified Authoritative Preconditions:** Target versions, distinct Alice and Bob user identities/roles, Alice file/KB ownership, Bob `GET /api/v1/files/{{id}}` metadata access (read-only metadata check; does not test or grant permission to read file content, and write permissions are not tested destructively), and {FIXTURE_BASELINE["content_length_bytes"]}-byte baseline integrity were independently verified via authoritative server GET routes.

---

## 3. Environment & Version Comparison

| Parameter | Vulnerable Target (v0.8.5) | Patched Target (v0.8.6) |
| :--- | :--- | :--- |
| **Image Tag** | `v0.8.5` | `v0.8.6` |
| **Pinned Digest** | `sha256:6251d208f91373f755c6a42abdbf740d003775dcf2d78b8811a213a822e7350b` | `sha256:4938a90d0b0fb2a7c361a254211704fab72e748c4c7649e5729947fdc56d9dea` |
| **Local Port** | `127.0.0.1:13085` | `127.0.0.1:13086` |
| **Authorization Check** | Omitted in `backend/open_webui/routers/retrieval.py:2595-2673` | Enforced in `backend/open_webui/routers/retrieval.py:2647-2667` |
| **Baseline Hash** | `{FIXTURE_BASELINE["sha256"]}` | `{FIXTURE_BASELINE["sha256"]}` |
| **Baseline Size** | {FIXTURE_BASELINE["content_length_bytes"]} bytes | {FIXTURE_BASELINE["content_length_bytes"]} bytes |

---

## 4. Exact Execution Commands

### A. Direct Exploit Reproduction
```bash
# Target v0.8.5 (Vulnerable)
python3 tests/integration/openwebui_cve_2026_28788/scripts/reproduce_cve.py \\
  --setup-file /tmp/setup-v085.json \\
  --output /tmp/reproduce-v085.json

# Target v0.8.6 (Patched)
python3 tests/integration/openwebui_cve_2026_28788/scripts/reproduce_cve.py \\
  --setup-file /tmp/setup-v086.json \\
  --output /tmp/reproduce-v086.json
```

### B. Firedamp Behavioral Regression Probe
```bash
# Target v0.8.5 (Vulnerable)
python3 tests/integration/openwebui_cve_2026_28788/scripts/run_firedamp_probe.py \\
  --setup-file /tmp/setup-v085.json \\
  --output /tmp/firedamp-v085.json

# Target v0.8.6 (Patched)
python3 tests/integration/openwebui_cve_2026_28788/scripts/run_firedamp_probe.py \\
  --setup-file /tmp/setup-v086.json \\
  --output /tmp/firedamp-v086.json
```

### C. Post-Test Fixture Restoration & Final Read-Only Verification
```bash
# Restore v0.8.5 baseline content and KB membership (intentional exit code 2: vector absence unverified)
python3 tests/integration/openwebui_cve_2026_28788/scripts/reset_fixture.py \\
  --setup-file /tmp/setup-v085.json

# Capture independent read-only verification for both targets
python3 tests/integration/openwebui_cve_2026_28788/scripts/capture_final_fixture_verification.py \\
  --setup-v085 /tmp/setup-v085.json \\
  --setup-v086 /tmp/setup-v086.json \\
  --output /tmp/final-fixture-verification.json
```

---

## 5. Vulnerable vs. Patched Live Outcomes

### A. Direct Exploit Reproduction vs. Firedamp Probe Matrix

| Evidence Stage / Metric | Open WebUI v0.8.5 (Vulnerable) | Open WebUI v0.8.6 (Patched) |
| :--- | :--- | :--- |
| **1. Direct Exploit — HTTP Status** | `{v085_http_status}` | `{v086_http_status}` (per-file error in JSON body, not HTTP 403) |
| **1. Direct Exploit — Batch Payload** | `results: [{{file_id: TARGET_FILE, status: "{v085_status}"}}]` | `results: []`, `errors: [{{file_id: TARGET_FILE, status: "failed"}}]` — error: {v086_err_msg} |
| **1. Direct Exploit — Verdict** | `VULNERABLE_CONFIRMED` | `PATCHED_CONFIRMED` |
| **1. Direct Exploit — Post-Attack SHA-256** | `{v085_post_sha}` | `{v086_post_sha}` |
| **1. Direct Exploit — Victim File Mutated** | **YES** (Bob tracer verified in Alice's content) | **NO** (Original content remained intact) |
| **2. Firedamp Probe — Verdict** | `COMPROMISED` | `CLEAN` |
| **2. Firedamp Probe — Severity** | `direct_leak` (`is_vulnerable: true`) | `none` (`is_vulnerable: false`, `is_clean: true`) |
| **2. Firedamp Probe — Canary Leaked** | {v085_canaries_display} | {v086_canaries_display} |

---

## 6. Fixture Baseline, Restoration & Final Independent Verification

### 1. Original Fixture Baseline
- Pre-test content length: {FIXTURE_BASELINE["content_length_bytes"]} bytes
- Baseline SHA-256: `{FIXTURE_BASELINE["sha256"]}`

### 2. Post-Test Fixture Restoration (Open WebUI v0.8.5)
- **Reset Status:** `{reset_v085["status"]}` (executed via `reset_fixture.py --setup-file /tmp/setup-v085.json`, exiting with intentional code 2 because exhaustive vector cleanup is not claimed).
- **Content & Membership Restored:**
  - Original `{reset_v085["content_length"]}`-byte content restored; post-reset SHA-256 `{reset_v085["sha256"]}` verified (`verified_hash: {str(reset_v085["verified_hash"]).lower()}`).
  - Alice file ownership re-verified (`verified_owner: {str(reset_v085["verified_owner"]).lower()}`).
  - Target KB membership re-verified (`verified_kb_membership: {str(reset_v085["verified_kb_membership"]).lower()}`).
  - {neighbor_line}
- **Patched Target Status (v0.8.6):** Reset was not needed because Open WebUI v0.8.6 rejected the unauthorized batch modification and left Alice's original content intact.

### 3. Vector Cleanup Verification Limitations
- A targeted vector-removal request was accepted (`vector_removal_request_accepted: {str(reset_v085["vector_removal_request_accepted"]).lower()}`).
- The post-reset top-k retrieval diagnostic returned no attacker marker (`vector_cleanup_verification: {reset_v085["vector_cleanup_verification"]}`).
- **Non-Exhaustive Limitation:** This post-reset top-k diagnostic is **not exhaustive proof of vector absence**. Because public retrieval endpoints are nearest-neighbor/top-k queries rather than exhaustive vector-store inspections, **exhaustive vector cleanup remains unverified** (`verified_vector_cleanup: {str(reset_v085["verified_vector_cleanup"]).lower()}`). Content restoration must not be conflated with exhaustive vector cleanup.

### 4. Final Independent Read-Only Fixture Verification (v0.8.5 & v0.8.6)
Both live targets independently passed `verify_setup_target(..., require_baseline=True)` in read-only mode (`verification_mode: {final_verification["verification_mode"]}`, `read_only: {str(final_verification["read_only"]).lower()}`):

| Verification Field | Open WebUI v0.8.5 | Open WebUI v0.8.6 |
| :--- | :--- | :--- |
| **Expected / Verified Version** | `{fv_085["expected_version"]}` / `{fv_085["verified_version"]}` | `{fv_086["expected_version"]}` / `{fv_086["verified_version"]}` |
| **Loopback URL** | `{fv_085["target_url"]}` | `{fv_086["target_url"]}` |
| **Baseline Verified** | `{str(fv_085["baseline_verified"]).lower()}` | `{str(fv_086["baseline_verified"]).lower()}` |
| **Content Length** | `{fv_085["content_length"]}` bytes | `{fv_086["content_length"]}` bytes |
| **Original SHA-256** | {fv_085_sha_match} (`{fv_085["original_sha256"]}`) | {fv_086_sha_match} (`{fv_086["original_sha256"]}`) |
| **Target Remains in Alice's KB** | `{str(fv_085["target_in_alice_kb"]).lower()}` (`{fv_085["kb_file_count"]}` file(s) in KB) | `{str(fv_086["target_in_alice_kb"]).lower()}` (`{fv_086["kb_file_count"]}` file(s) in KB) |
| **Ownership, Identities & GET Metadata** | Verified (`{str(fv_085["identities_and_read_metadata_verified"]).lower()}`; Bob GET file metadata only, not content read permission) | Verified (`{str(fv_086["identities_and_read_metadata_verified"]).lower()}`; Bob GET file metadata only, not content read permission) |

---

## 7. Researcher Reproduction Guide

To independently reproduce this differential verification in a local sandbox:

1. **Start Disposable Lab Containers:**
   ```bash
   sudo docker compose -f tests/integration/openwebui_cve_2026_28788/compose.yaml up -d
   ```
2. **Wait for Health Checks:**
   ```bash
   curl -f http://127.0.0.1:13085/health
   curl -f http://127.0.0.1:13086/health
   ```
3. **Provision Target Fixtures:**
   ```bash
   python3 tests/integration/openwebui_cve_2026_28788/scripts/setup_lab.py --url http://127.0.0.1:13085 --target-name v085 --output /tmp/setup-v085.json
   python3 tests/integration/openwebui_cve_2026_28788/scripts/setup_lab.py --url http://127.0.0.1:13086 --target-name v086 --output /tmp/setup-v086.json
   ```
4. **Execute Direct Reproduction, Probes, Reset, and Final Verification:**
   Run the commands listed in Section 4 (ensuring setup JSON files containing tokens remain strictly outside `--raw-dir`).
5. **Collect and Sanitize Evidence:**
   ```bash
   python3 tests/integration/openwebui_cve_2026_28788/scripts/collect_evidence.py \\
     --mode live \\
     --raw-dir ~/firedamp-evidence/cve-2026-28788/live-raw \\
     --output-dir ~/firedamp-evidence/cve-2026-28788/sanitized
   ```
6. **Teardown & Cleanup:**
   ```bash
   bash tests/integration/openwebui_cve_2026_28788/scripts/cleanup_lab.sh --use-sudo
   ```

---

## 8. Limitations & Boundary Scope

- **Endpoint Scope:** This evidence specifically substantiates authorization enforcement on `POST /api/v1/retrieval/process/files/batch`. It does not evaluate other API endpoints or other CVEs.
- **Vector Cleanup Scope:** Post-reset checks verify restored file content (`File.data.content`), ownership, and KB membership, while public nearest-neighbor top-k retrieval cannot exhaustively prove vector absence across the embedding store.
- **Environment Scope:** Live evidence reflects isolated single-node containerized Open WebUI lab instances bound to loopback (`127.0.0.1`); offline simulation suites in `simulations/` are strictly separate and never substituted as live evidence.
- **Threat Model Scope:** Assumes an authenticated attacker who has read-only access to a knowledge base containing another user's file. Network-layer MitM, container breakout, and token theft vectors are outside the scope of this test.
"""


def sanitize_evidence_bundle(raw_dir: Path, output_dir: Path) -> Dict[str, Any]:
    """
    Ingests raw evidence reports from raw_dir, snapshots cryptographic hashes,
    validates semantic and differential integrity across all reports,
    sanitizes internal UUIDs with role-based placeholders, writes sanitized artifacts
    to output_dir, and produces an authoritative manifest.json.
    Guarantees raw files remain unmodified.
    """
    if not raw_dir.exists():
        raise FileNotFoundError(f"Raw evidence directory not found: {raw_dir}")

    for forbidden in ("setup-v085.json", "setup-v086.json"):
        if (raw_dir / forbidden).exists():
            raise ValueError(
                f"Refusing to ingest raw evidence directory containing credential-bearing setup file '{forbidden}'"
            )

    # 1. Safely open each required raw input once and snapshot exact bytes in memory
    raw_bytes_snapshot: Dict[str, bytes] = {}
    raw_files_info = {}
    initial_hashes = {}
    for filename in REQUIRED_RAW_FILES:
        file_path = raw_dir / filename
        if not file_path.exists():
            raise FileNotFoundError(f"Required raw evidence file missing: {file_path}")
        if file_path.is_symlink():
            raise ValueError(f"Refusing symlink raw evidence file: {file_path}")

        fd = -1
        f = None
        try:
            fd = os.open(file_path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
            st = os.fstat(fd)
            if not stat.S_ISREG(st.st_mode):
                raise ValueError(
                    f"Refusing non-regular raw evidence file {filename} (mode: {stat.S_IMODE(st.st_mode):04o})"
                )
            f = open(fd, "rb", closefd=True)
            exact_bytes = f.read()
        except Exception as e:
            if f is not None:
                try:
                    f.close()
                except Exception:
                    pass
            elif fd >= 0:
                try:
                    os.close(fd)
                except Exception:
                    pass
            raise ValueError(f"Failed to securely read raw evidence file {filename}: {e}") from e
        finally:
            if f is not None:
                try:
                    f.close()
                except Exception:
                    pass

        exact_hash = hashlib.sha256(exact_bytes).hexdigest()
        raw_bytes_snapshot[filename] = exact_bytes
        initial_hashes[filename] = exact_hash
        raw_files_info[filename] = {
            "sha256": exact_hash,
            "verified": True,
        }

    # 2. Parse and validate the exact same in-memory snapshot without reopening input paths
    try:
        raw_firedamp_v085 = json.loads(raw_bytes_snapshot["firedamp-v085.json"].decode("utf-8"))
        raw_firedamp_v086 = json.loads(raw_bytes_snapshot["firedamp-v086.json"].decode("utf-8"))
        raw_reproduce_v085 = json.loads(raw_bytes_snapshot["reproduce-v085.json"].decode("utf-8"))
        raw_reproduce_v086 = json.loads(raw_bytes_snapshot["reproduce-v086.json"].decode("utf-8"))
        raw_reset_v085 = json.loads(raw_bytes_snapshot["reset-v085.json"].decode("utf-8"))
        raw_final_verification = json.loads(
            raw_bytes_snapshot["final-fixture-verification.json"].decode("utf-8")
        )
    except (json.JSONDecodeError, UnicodeDecodeError) as e:
        raise ValueError(f"Malformed raw evidence JSON: {e}")

    # 3. Validate semantic, reset, final-verification, and differential integrity
    validate_raw_reports(
        raw_firedamp_v085,
        raw_firedamp_v086,
        raw_reproduce_v085,
        raw_reproduce_v086,
        raw_reset_v085,
        raw_final_verification,
    )

    # 4. Sanitize data structures
    sanitized_v085 = sanitize_firedamp_report(raw_firedamp_v085, "v085")
    sanitized_v086 = sanitize_firedamp_report(raw_firedamp_v086, "v086")
    sanitized_rep_v085 = sanitize_reproduce_report(raw_reproduce_v085, "v085")
    sanitized_rep_v086 = sanitize_reproduce_report(raw_reproduce_v086, "v086")
    sanitized_reset_v085 = sanitize_reset_report(raw_reset_v085)
    sanitized_final_verif = sanitize_final_verification_report(raw_final_verification)
    readme_content = generate_bundle_readme(
        sanitized_v085,
        sanitized_v086,
        sanitized_rep_v085,
        sanitized_rep_v086,
        sanitized_reset_v085,
        sanitized_final_verif,
    )

    # 5. Validate output directory destination
    abs_output_dir = Path(os.path.abspath(os.fspath(output_dir)))
    if abs_output_dir.is_symlink():
        raise ValueError(f"Refusing symlink output directory: {abs_output_dir}")
    for parent in abs_output_dir.parents:
        if parent.is_symlink():
            raise ValueError(f"Refusing symlinked parent directory component for output directory: {parent}")
    if abs_output_dir.exists():
        if not abs_output_dir.is_dir():
            raise ValueError(f"Refusing non-directory output destination: {abs_output_dir}")
        for p in abs_output_dir.iterdir():
            if p.is_symlink():
                raise ValueError(f"Refusing pre-existing symlink in output directory: {p.name}")
            raise ValueError(
                f"Refusing non-empty output directory to guarantee atomic publication: {abs_output_dir} ({p.name})"
            )

    # 6. Create isolated staging directory with restrictive 0700 permissions
    abs_output_parent = abs_output_dir.parent
    abs_output_parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    staging_dir = Path(tempfile.mkdtemp(prefix=".staging_bundle_", dir=abs_output_parent))
    os.chmod(staging_dir, 0o700)

    try:
        # Write sanitized outputs securely into staging directory (0600 before write, O_NOFOLLOW)
        file_map = {
            "sanitized-v085.json": json.dumps(sanitized_v085, indent=2) + "\n",
            "sanitized-v086.json": json.dumps(sanitized_v086, indent=2) + "\n",
            "sanitized-reproduce-v085.json": json.dumps(sanitized_rep_v085, indent=2) + "\n",
            "sanitized-reproduce-v086.json": json.dumps(sanitized_rep_v086, indent=2) + "\n",
            "sanitized-reset-v085.json": json.dumps(sanitized_reset_v085, indent=2) + "\n",
            "sanitized-final-fixture-verification.json": json.dumps(sanitized_final_verif, indent=2) + "\n",
            "README.md": readme_content,
        }

        sanitized_hashes = {}
        for fname, content in file_map.items():
            staged_file = staging_dir / fname
            _write_secure_output(staged_file, content)
            sanitized_hashes[fname] = {
                "sha256": sha256_file(staged_file)
            }

        # 7. Build manifest.json in staging directory
        preserved_count = raw_reset_v085["preserved_other_file_count"]
        neighbor_summary = (
            "0 other files were present in the disposable KB to preserve"
            if preserved_count == 0
            else (
                f"reset reported preserved_other_file_count={preserved_count} with matching final KB "
                f"membership count ({1 + preserved_count} total); individual neighboring file contents and "
                "identities not separately verified"
            )
        )
        final_v085 = raw_final_verification["targets"]["v0.8.5"]
        final_v086 = raw_final_verification["targets"]["v0.8.6"]

        now_utc = datetime.datetime.now(datetime.timezone.utc)
        manifest = {
            "evidence_id": f"cve-2026-28788-sanitized-bundle-{now_utc.strftime('%Y%m%d')}",
            "cve_id": "CVE-2026-28788",
            "advisory": "GHSA-jjp7-g2jw-wh3j",
            "collection_date": now_utc.strftime("%Y-%m-%d"),
            "sanitizer_version": "1.1.0",
            "sanitization_method": (
                "Role-based placeholder pseudonymization for known internal resource/user UUIDs and run identifiers; "
                "regex scrubbing of Bearer tokens, JWTs, Authorization/Cookie headers, passwords, secret key-value pairs, "
                "URL userinfo, and standalone UUIDs across all forwarded free-text fields (target_response, reason, "
                "tracer_marker, errors, vector_cleanup_note); preservation of synthetic CANARY-* tokens, cryptographic "
                "hashes, batch process statuses, and reset diagnostics."
            ),
            "provenance_notes": (
                "Collector-computed hashes cryptographically bind the exact in-memory bytes of raw and "
                "sanitized artifacts to this manifest, and post-execution disk re-reading verifies final-state "
                "hash consistency of raw files; this confirms internal bundle consistency and final-state disk "
                "matching, but does not prove the absence of transient external modifications during collection, "
                "and does not establish external cryptographic origin authentication for operator-supplied artifacts."
            ),
            "target_images": PINNED_IMAGE_DIGESTS,
            "fixture_baseline": FIXTURE_BASELINE,
            "fixture_reset_verification": {
                "v0.8.5": {
                    "reset_status": raw_reset_v085["status"],
                    "target_version": raw_reset_v085["target_version"],
                    "content_length": raw_reset_v085["content_length"],
                    "sha256": raw_reset_v085["sha256"],
                    "preserved_other_file_count": preserved_count,
                    "verified_owner": raw_reset_v085["verified_owner"],
                    "verified_hash": raw_reset_v085["verified_hash"],
                    "verified_kb_membership": raw_reset_v085["verified_kb_membership"],
                    "vector_removal_request_accepted": raw_reset_v085["vector_removal_request_accepted"],
                    "vector_cleanup_verification": raw_reset_v085["vector_cleanup_verification"],
                    "verified_vector_cleanup": raw_reset_v085["verified_vector_cleanup"],
                    "source_artifact": "reset-v085.json",
                    "verification_mode": "operator_supplied_schema_validated",
                    "schema_validated": True,
                    "cryptographic_origin_authenticated": False,
                    "limitation": (
                        "The pinned public retrieval query is nearest-neighbor/top-k and cannot exhaustively prove "
                        "absence of all vectors. Content restoration does not prove exhaustive vector cleanup. "
                        "Targeted removal was accepted and post-reset top-k returned no attacker marker, "
                        "so exhaustive vector cleanup remains unverified (verified_vector_cleanup=false)."
                    ),
                    "details": (
                        f"Content ({raw_reset_v085['content_length']} bytes, baseline SHA-256), Alice ownership, "
                        f"and target KB membership verified after reset; {neighbor_summary}. Targeted vector removal "
                        f"accepted ({raw_reset_v085['vector_cleanup_verification']}); exhaustive vector cleanup remains unverified."
                    ),
                },
                "v0.8.6": {
                    "reset_status": "NOT_NEEDED",
                    "target_version": final_v086["verified_version"],
                    "content_length": final_v086["content_length"],
                    "sha256": final_v086["original_sha256"],
                    "baseline_verified": final_v086["baseline_verified"],
                    "target_in_alice_kb": final_v086["target_in_alice_kb"],
                    "kb_file_count": final_v086["kb_file_count"],
                    "identities_and_read_metadata_verified": final_v086["identities_and_read_metadata_verified"],
                    "source_artifact": "final-fixture-verification.json",
                    "verification_mode": raw_final_verification["verification_mode"],
                    "schema_validated": True,
                    "cryptographic_origin_authenticated": False,
                    "details": (
                        f"Reset was not needed because the unauthorized batch overwrite was rejected and Alice's "
                        f"original {final_v086['content_length']}-byte baseline content remained intact throughout execution, "
                        "confirmed by final independent read-only verification."
                    ),
                },
            },
            "final_fixture_verification": {
                "source_artifact": "final-fixture-verification.json",
                "verification_mode": raw_final_verification["verification_mode"],
                "live_execution": raw_final_verification["live_execution"],
                "read_only": raw_final_verification["read_only"],
                "vector_cleanup_verified": raw_final_verification["vector_cleanup_verified"],
                "schema_validated": True,
                "cryptographic_origin_authenticated": False,
                "targets": {
                    "v0.8.5": {
                        "expected_version": final_v085["expected_version"],
                        "verified_version": final_v085["verified_version"],
                        "target_url": final_v085["target_url"],
                        "baseline_verified": final_v085["baseline_verified"],
                        "original_sha256": final_v085["original_sha256"],
                        "content_length": final_v085["content_length"],
                        "target_in_alice_kb": final_v085["target_in_alice_kb"],
                        "kb_file_count": final_v085["kb_file_count"],
                        "identities_and_read_metadata_verified": final_v085["identities_and_read_metadata_verified"],
                    },
                    "v0.8.6": {
                        "expected_version": final_v086["expected_version"],
                        "verified_version": final_v086["verified_version"],
                        "target_url": final_v086["target_url"],
                        "baseline_verified": final_v086["baseline_verified"],
                        "original_sha256": final_v086["original_sha256"],
                        "content_length": final_v086["content_length"],
                        "target_in_alice_kb": final_v086["target_in_alice_kb"],
                        "kb_file_count": final_v086["kb_file_count"],
                        "identities_and_read_metadata_verified": final_v086["identities_and_read_metadata_verified"],
                    },
                },
            },
            "raw_evidence_files": raw_files_info,
            "sanitized_output_files": sanitized_hashes,
            "intentionally_redacted_fields": [
                {
                    "original_field": "alice_user_id / owner_user_id",
                    "sanitized_placeholder": "VICTIM_USER",
                    "reason": "Internal user UUID pseudonymization",
                },
                {
                    "original_field": "bob_user_id",
                    "sanitized_placeholder": "ATTACKER_USER",
                    "reason": "Internal user UUID pseudonymization",
                },
                {
                    "original_field": "kb_id",
                    "sanitized_placeholder": "TARGET_KNOWLEDGE_BASE",
                    "reason": "Internal knowledge base UUID pseudonymization",
                },
                {
                    "original_field": "disposable_file_id / target_file_id / file_id",
                    "sanitized_placeholder": "TARGET_FILE",
                    "reason": "Internal file UUID pseudonymization",
                },
                {
                    "original_field": "run_id",
                    "sanitized_placeholder": "firedamp-lab-run-v085 / firedamp-lab-run-v086",
                    "reason": "Scan run execution UUID normalization",
                },
            ],
        }

        manifest_path = staging_dir / "manifest.json"
        _write_secure_output(manifest_path, json.dumps(manifest, indent=2) + "\n")
        sanitized_hashes["manifest.json"] = {
            "sha256": sha256_file(manifest_path)
        }

        # 8. Post-execution raw files final-state consistency verification
        # Re-reading raw files verifies final-state consistency on disk with initial hashes;
        # note that while this confirms final on-disk content matches, SHA-256 binding of the exact
        # in-memory snapshot guarantees the artifacts actually processed and recorded in the manifest.
        for filename, expected_hash in initial_hashes.items():
            file_path = raw_dir / filename
            after_hash = sha256_file(file_path)
            if after_hash != expected_hash:
                raise RuntimeError(
                    f"INTEGRITY VIOLATION: Raw evidence file {filename} final-state disk hash mismatch!"
                )

        # 9. Verify permissions and SHA-256 integrity on all staged artifacts before publication
        all_staged = list(file_map.keys()) + ["manifest.json"]
        for fname in all_staged:
            staged_p = staging_dir / fname
            st = staged_p.stat()
            if stat.S_IMODE(st.st_mode) & 0o077:
                raise RuntimeError(f"Staged file {fname} has insecure permissions: {stat.S_IMODE(st.st_mode):04o}")
            actual_sha = sha256_file(staged_p)
            if actual_sha != sanitized_hashes[fname]["sha256"]:
                raise RuntimeError(f"Staged file {fname} SHA-256 integrity mismatch")

        # 10. True atomic directory-level publication into abs_output_dir via single atomic rename
        if abs_output_dir.is_symlink():
            raise ValueError(f"Refusing symlink output directory: {abs_output_dir}")
        for parent in abs_output_dir.parents:
            if parent.is_symlink():
                raise ValueError(f"Refusing symlinked parent directory component for output directory: {parent}")

        if abs_output_dir.exists():
            if not abs_output_dir.is_dir():
                raise ValueError(f"Refusing non-directory output destination: {abs_output_dir}")
            for p in abs_output_dir.iterdir():
                raise ValueError(
                    f"Refusing non-empty output directory prior to publication: {abs_output_dir} ({p.name})"
                )

        # Enforce strict 0700 permissions on staging directory before atomic rename
        os.chmod(staging_dir, 0o700)
        try:
            os.replace(staging_dir, abs_output_dir)
        except OSError as e:
            raise RuntimeError(f"Atomic directory publication failed for {abs_output_dir}: {e}") from e

        return manifest
    finally:
        if staging_dir.exists():
            shutil.rmtree(staging_dir, ignore_errors=True)


def main() -> None:
    parser = argparse.ArgumentParser(description="Collect CVE-2026-28788 Evidence Bundle")
    parser.add_argument("--mode", choices=["auto", "offline", "live"], default="auto", help="Execution mode")
    parser.add_argument("--use-sudo", action="store_true", default=(os.environ.get("USE_SUDO") == "1"), help="Use sudo -n for Docker commands")
    parser.add_argument("--output-dir", default=None, help="Explicit output directory")
    parser.add_argument("--raw-dir", default=None, help="Directory containing raw JSON evidence files to sanitize and bundle")
    args = parser.parse_args()

    if args.raw_dir:
        if args.mode != "live":
            print(
                f"ERROR: Ingesting raw evidence via --raw-dir requires explicit --mode live (current mode: '{args.mode}'). "
                f"Modes 'auto' and 'offline' cannot ingest live raw reports. Aborting fail-closed."
            )
            sys.exit(1)
        raw_path = Path(args.raw_dir)
        out_path = Path(args.output_dir) if args.output_dir else raw_path / "sanitized"
        print(f"=== Sanitizing Evidence from {raw_path} into {out_path} ===")
        manifest = sanitize_evidence_bundle(raw_path, out_path)
        print("✓ Evidence sanitization and bundling complete.")
        print(f"  Output directory: {out_path}")
        for item in sorted(out_path.iterdir()):
            print(f"  - {item.name}")
        return

    timestamp_str = datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%d_%H%M%SZ")

    if args.mode == "live":
        print(
            "ERROR: Live mode requires validated raw reports supplied via --raw-dir. "
            "Refusing to manufacture or substitute simulated results in live mode. "
            "Live evidence must be supplied through validated raw reports. Aborting fail-closed."
        )
        sys.exit(1)

    # In legacy non-raw-dir mode, both 'offline' and 'auto' operate strictly as offline simulation.
    # Auto mode never checks Docker daemon or generates live verdicts.
    is_live = False
    execution_category = "offline_simulation"
    docker_daemon_status = {
        "accessible": False,
        "details": "Docker daemon checks skipped in offline simulation mode.",
    }
    docker_cli = "NOT_CHECKED"
    compose_cli = "NOT_CHECKED"

    if args.output_dir:
        run_dir = Path(args.output_dir)
    else:
        run_dir = LAB_DIR / "evidence" / execution_category / f"run_{timestamp_str}"

    run_dir.mkdir(parents=True, exist_ok=True)
    print(f"=== Collecting CVE-2026-28788 Evidence ({execution_category}) into {run_dir} ===")

    # 1. Environment Info
    image_digests = {
        "v0.8.5": {
            "image": "ghcr.io/open-webui/open-webui:v0.8.5@sha256:6251d208f91373f755c6a42abdbf740d003775dcf2d78b8811a213a822e7350b",
            "tag": "v0.8.5",
            "mediaType": "application/vnd.docker.distribution.manifest.list.v2+json",
            "linux_amd64_digest": "sha256:6251d208f91373f755c6a42abdbf740d003775dcf2d78b8811a213a822e7350b",
        },
        "v0.8.6": {
            "image": "ghcr.io/open-webui/open-webui:v0.8.6@sha256:4938a90d0b0fb2a7c361a254211704fab72e748c4c7649e5729947fdc56d9dea",
            "tag": "v0.8.6",
            "mediaType": "application/vnd.docker.distribution.manifest.list.v2+json",
            "linux_amd64_digest": "sha256:4938a90d0b0fb2a7c361a254211704fab72e748c4c7649e5729947fdc56d9dea",
        },
    }

    env_data = {
        "timestamp": timestamp_str,
        "execution_mode": "offline_simulation",
        "live_execution": False,
        "platform": {
            "system": platform.system(),
            "release": platform.release(),
            "version": platform.version(),
            "machine": platform.machine(),
            "python_version": sys.version,
        },
        "git": get_git_info(),
        "docker": {
            "cli_version": docker_cli,
            "compose_version": compose_cli,
            "daemon": docker_daemon_status,
        },
        "pinned_images": image_digests,
        "lab_ports": {
            "vulnerable_port": "127.0.0.1:13085",
            "patched_port": "127.0.0.1:13086",
        },
    }
    (run_dir / "environment.json").write_text(json.dumps(env_data, indent=2), encoding="utf-8")

    # Image Manifest JSON
    (run_dir / "image-manifest.json").write_text(json.dumps(image_digests, indent=2), encoding="utf-8")

    # 2. Controls / Simulation Proofs
    sim_results = run_offline_simulations()
    (run_dir / "controls.json").write_text(json.dumps(sim_results, indent=2), encoding="utf-8")

    # 3. Setup Alice and Setup Bob (Separate, sanitized JSONs)
    setup_alice = {
        "execution_mode": "offline_simulation",
        "live_execution": False,
        "target_execution_status": "NOT_RUN",
        "persona": "Alice",
        "role": "victim_resource_owner",
        "user_id": "usr-alice-disposable-01",
        "email": "alice@lab.local",
        "auth_token": "[REDACTED_ALICE_BEARER_TOKEN]",
        "knowledge_base": {
            "id": "kb-alice-shared-cve28788",
            "name": "Alice Lab Knowledge Base",
        },
        "disposable_file": {
            "id": "file-disposable-alice-cve28788",
            "filename": "alice_disposable.txt",
            "content_baseline_sha256": "4b227777d4dd1fc61c6f884f48641d02b4d121d3fd328cb08b5531fcacdabf8a",
        },
    }
    (run_dir / "setup-alice.json").write_text(json.dumps(setup_alice, indent=2), encoding="utf-8")

    setup_bob = {
        "execution_mode": "offline_simulation",
        "live_execution": False,
        "target_execution_status": "NOT_RUN",
        "persona": "Bob",
        "role": "attacker_tenant",
        "user_id": "usr-bob-disposable-02",
        "email": "bob@lab.local",
        "auth_token": "[REDACTED_BOB_BEARER_TOKEN]",
        "shared_kb_access": {
            "kb_id": "kb-alice-shared-cve28788",
            "permission": "read_only",
        },
    }
    (run_dir / "setup-bob.json").write_text(json.dumps(setup_bob, indent=2), encoding="utf-8")

    # 4. Vulnerable and Patched Target Files (with explicit offline simulation schema)
    vulnerable_data = {
        "execution_mode": "offline_simulation",
        "live_execution": False,
        "target_execution_status": "NOT_RUN",
        "simulated_expected_verdict": "COMPROMISED",
        "observed_verdict": "NOT_RUN",
        "target_version": "v0.8.5",
        "target_image": image_digests["v0.8.5"]["image"],
        "target_url": "http://127.0.0.1:13085",
        "upstream_source_contract": {
            "file": "backend/open_webui/routers/retrieval.py",
            "lines": "2580-2582 (BatchProcessFilesForm), 2595-2673 (process_files_batch)",
            "behavior": "No file ownership check exists before processing the submitted file",
        },
        "target_file_id": "file-disposable-alice-cve28788",
        "http_status": None,
        "batch_response": {
            "simulated_expected_results": [{"file_id": "file-disposable-alice-cve28788", "status": "completed"}],
            "simulated_expected_errors": [],
            "results": [],
            "errors": [],
        },
        "baseline_readback_sha256": "4b227777d4dd1fc61c6f884f48641d02b4d121d3fd328cb08b5531fcacdabf8a",
        "post_readback_sha256": None,
        "tracer_found_in_alice_indexed_content": False,
        "observed_exploitation": False,
        "notes": "Offline simulation: based on upstream Open WebUI v0.8.5 contract. Target was NOT executed.",
    }
    (run_dir / "vulnerable-v085.json").write_text(json.dumps(vulnerable_data, indent=2), encoding="utf-8")

    patched_data = {
        "execution_mode": "offline_simulation",
        "live_execution": False,
        "target_execution_status": "NOT_RUN",
        "simulated_expected_verdict": "CLEAN",
        "observed_verdict": "NOT_RUN",
        "target_version": "v0.8.6",
        "target_image": image_digests["v0.8.6"]["image"],
        "target_url": "http://127.0.0.1:13086",
        "upstream_source_contract": {
            "file": "backend/open_webui/routers/retrieval.py",
            "lines": "2611-2613 (BatchProcessFilesForm), 2626-2724 (process_files_batch), 2647-2667 (ownership enforcement)",
            "behavior": "Explicitly verifies db_file.user_id == user.id or user.role == 'admin'; rejects unauthorized batch overwrite with per-file error",
        },
        "target_file_id": "file-disposable-alice-cve28788",
        "http_status": None,
        "batch_response": {
            "simulated_expected_results": [],
            "simulated_expected_errors": [
                {
                    "file_id": "file-disposable-alice-cve28788",
                    "status": "failed",
                    "error": "Permission denied: not file owner",
                }
            ],
            "results": [],
            "errors": [],
        },
        "baseline_readback_sha256": "4b227777d4dd1fc61c6f884f48641d02b4d121d3fd328cb08b5531fcacdabf8a",
        "post_readback_sha256": None,
        "tracer_found_in_alice_indexed_content": False,
        "observed_exploitation": False,
        "notes": "Offline simulation: based on upstream Open WebUI v0.8.6 contract. Target was NOT executed.",
    }
    (run_dir / "patched-v086.json").write_text(json.dumps(patched_data, indent=2), encoding="utf-8")

    # 5. Firedamp Probe Results
    firedamp_v085 = {
        "execution_mode": "offline_simulation",
        "live_execution": False,
        "target_execution_status": "NOT_RUN",
        "simulated_expected_verdict": "COMPROMISED",
        "cve_id": "CVE-2026-28788",
        "target_version": "v0.8.5",
        "probe_severity": None,
        "probe_status": "NOT_RUN",
        "target_response": "SIMULATION ONLY: Target was NOT executed. Live probe was not run.",
        "pre_write_gate_passed": False,
        "scan_registry_verified": False,
        "cleanup_status": "NOT_RUN (Offline simulation: no resources provisioned or deleted)",
    }
    (run_dir / "firedamp-v085.json").write_text(json.dumps(firedamp_v085, indent=2), encoding="utf-8")

    firedamp_v086 = {
        "execution_mode": "offline_simulation",
        "live_execution": False,
        "target_execution_status": "NOT_RUN",
        "simulated_expected_verdict": "CLEAN",
        "cve_id": "CVE-2026-28788",
        "target_version": "v0.8.6",
        "probe_severity": None,
        "probe_status": "NOT_RUN",
        "target_response": "SIMULATION ONLY: Target was NOT executed. Live probe was not run.",
        "pre_write_gate_passed": False,
        "scan_registry_verified": False,
        "cleanup_status": "NOT_RUN (Offline simulation: no resources provisioned or deleted)",
    }
    (run_dir / "firedamp-v086.json").write_text(json.dumps(firedamp_v086, indent=2), encoding="utf-8")

    # 6. Content Verification JSON
    content_verification = {
        "execution_mode": "offline_simulation",
        "live_execution": False,
        "target_file_id": "file-disposable-alice-cve28788",
        "baseline_readback_endpoint": "/api/v1/files/{file_id}/data/content",
        "original_content_sha256": "4b227777d4dd1fc61c6f884f48641d02b4d121d3fd328cb08b5531fcacdabf8a",
        "v0.8.5_post_attack": {
            "post_attack_sha256": None,
            "content_mutated": False,
            "tracer_detected": False,
            "verification_verdict": "NOT_RUN_SIMULATION_ONLY",
        },
        "v0.8.6_post_attack": {
            "post_attack_sha256": None,
            "content_mutated": False,
            "tracer_detected": False,
            "verification_verdict": "NOT_RUN_SIMULATION_ONLY",
        },
    }
    (run_dir / "content-verification.json").write_text(json.dumps(content_verification, indent=2), encoding="utf-8")

    # 7. Redacted HTTP Trace
    traces = [
        {
            "execution_mode": "offline_simulation",
            "live_execution": False,
            "status": "NOT_RUN",
            "details": "Offline simulation mode: no live HTTP traces recorded. Supply validated raw reports via --raw-dir for authenticated live traces.",
        }
    ]
    with open(run_dir / "http-trace-redacted.jsonl", "w", encoding="utf-8") as f:
        for t in traces:
            f.write(json.dumps(t) + "\n")

    # 8. Cleanup Verification JSON
    cleanup_data = {
        "execution_mode": "offline_simulation",
        "live_execution": False,
        "cleanup_policy": "STRICT_FAIL_CLOSED_TARGETED",
        "authorization_checks_tested": {
            "provisioned_by_current_run": False,
            "server_owner_matches_alice": False,
        },
        "unit_test_verification": "NOT_RUN_BY_COLLECTOR",
        "shell_syntax_validation": "NOT_RUN_BY_COLLECTOR",
        "actual_docker_removal": "NOT_RUN",
        "docker_cleanup_status": "NOT_RUN",
        "reason": "Offline simulation: no containers, networks, or volumes were created or deleted.",
        "status": "NOT_RUN",
    }
    (run_dir / "cleanup.json").write_text(json.dumps(cleanup_data, indent=2), encoding="utf-8")

    # 9. Top-Level evidence.json
    evidence_summary = {
        "evidence_id": f"cve-2026-28788-{execution_category}-{timestamp_str}",
        "cve_id": "CVE-2026-28788",
        "advisory": "GHSA-jjp7-g2jw-wh3j",
        "timestamp": timestamp_str,
        "execution_mode": "offline_simulation",
        "live_execution": False,
        "infrastructure_status": "OFFLINE_SIMULATION",
        "blocker_details": "Offline simulation mode: live execution requires validated raw reports supplied via --raw-dir.",
        "simulation_controls": {
            "tests_run": sim_results["tests_run"],
            "all_passed": sim_results["was_successful"],
        },
        "target_verdicts": {
            "v0.8.5": {
                "execution_status": "NOT_RUN",
                "simulated_expected_verdict": "COMPROMISED",
                "observed_verdict": "NOT_RUN",
            },
            "v0.8.6": {
                "execution_status": "NOT_RUN",
                "simulated_expected_verdict": "CLEAN",
                "observed_verdict": "NOT_RUN",
            },
        },
    }
    (run_dir / "evidence.json").write_text(json.dumps(evidence_summary, indent=2), encoding="utf-8")

    # 10. Human-Readable summary.md
    summary_md = f"""# CVE-2026-28788 Evidence Report (OFFLINE SIMULATION ONLY)

- **Timestamp:** {timestamp_str}
- **Advisory:** GHSA-jjp7-g2jw-wh3j
- **Vulnerability:** Open WebUI Cross-User File Overwrite via Batch Process (`POST /api/v1/retrieval/process/files/batch`)
- **Execution Mode:** `offline_simulation`
- **Live Execution Status:** `NOT_RUN (Offline simulation mode; live execution requires validated raw reports via --raw-dir)`

> [!WARNING]
> This evidence bundle represents an OFFLINE DETERMINISTIC SIMULATION. No real Open WebUI container was contacted or compromised during this run. Live evidence must be supplied through validated raw reports via --raw-dir.

---

## 1. Environment & Container Manifests

- **Host Platform:** {platform.system()} {platform.release()} ({platform.machine()})
- **Python Version:** {platform.python_version()}
- **Docker CLI:** {docker_cli}
- **Docker Compose:** {compose_cli}
- **Docker Daemon Accessibility:** `SKIPPED (Offline simulation mode)`

### Pinned Upstream Image Manifests

| Version | Pinned Image Reference | Architecture | Manifest Digest |
| :--- | :--- | :--- | :--- |
| **v0.8.5 (Vulnerable)** | `ghcr.io/open-webui/open-webui:v0.8.5@sha256:6251d208f91373f755c6a42abdbf740d003775dcf2d78b8811a213a822e7350b` | linux/amd64 | `sha256:6251d208f91373f755c6a42abdbf740d003775dcf2d78b8811a213a822e7350b` |
| **v0.8.6 (Patched)** | `ghcr.io/open-webui/open-webui:v0.8.6@sha256:4938a90d0b0fb2a7c361a254211704fab72e748c4c7649e5729947fdc56d9dea` | linux/amd64 | `sha256:4938a90d0b0fb2a7c361a254211704fab72e748c4c7649e5729947fdc56d9dea` |

---

## 2. Upstream Source Contract & Root Cause

### Open WebUI v0.8.5 (`backend/open_webui/routers/retrieval.py` lines 2595–2673; Form lines 2580–2582)
```python
# Lines 2580-2582: Form definition
class BatchProcessFilesForm(BaseModel):
    files: List[FileModel]
    collection_name: str

# Lines 2595-2673: process_files_batch
for file in form_data.files:
    text_content = file.data.get("content", "")
    file_updates.append(
        FileUpdateForm(
            hash=calculate_sha256_string(text_content),
            data={{"content": text_content}},
        )
    )
...
# After embedding generation:
for file_update, file_result in zip(file_updates, file_results):
    Files.update_file_by_id(id=file_result.file_id, form_data=file_update)
    file_result.status = "completed"
```
*Vulnerability:* The loop accepts any `file.id` provided in `form_data.files` and updates `File.data.content` in the database without checking whether `file.user_id` matches `user.id`. No file ownership check exists before processing.

### Open WebUI v0.8.6 Fix (`backend/open_webui/routers/retrieval.py` lines 2626–2724; Form lines 2611–2613; Ownership lines 2647–2667)
```python
# Lines 2647-2667: Ownership check
for file in form_data.files:
    # Ownership check: verify the requesting user owns the file or is an admin
    db_file = Files.get_file_by_id(file.id)
    if not db_file:
        file_errors.append(
            BatchProcessFilesResult(
                file_id=file.id,
                status="failed",
                error="File not found",
            )
        )
        continue
    if db_file.user_id != user.id and user.role != "admin":
        file_errors.append(
            BatchProcessFilesResult(
                file_id=file.id,
                status="failed",
                error="Permission denied: not file owner",
            )
        )
        continue
```
*Fix:* Explicitly validates `db_file.user_id == user.id or user.role == 'admin'`, returning per-file failure with `"Permission denied: not file owner"` in `errors`.

---

## 3. Evidence Matrix

| Target | Target Execution | Batch Process Response | Persisted Content | Expected Verdict | Observed Verdict |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **v0.8.5** | `NOT_RUN` | `None (Offline Simulation)` | **Not Observed** | `COMPROMISED` | `NOT_RUN` |
| **v0.8.6** | `NOT_RUN` | `None (Offline Simulation)` | **Not Observed** | `CLEAN` | `NOT_RUN` |

---

## 4. Deterministic Simulation Controls

- **Simulation Suite:** `tests/integration/openwebui_cve_2026_28788/simulations/test_response_classification.py`
- **Tests Executed:** {sim_results['tests_run']}
- **Tests Passed:** {sim_results['tests_run'] - sim_results['failures'] - sim_results['errors']}
- **Status:** All deterministic edge-case tests passed with 100% success.

---

## 5. Cleanup Status & Safety Controls

- **Actual Docker Teardown:** `NOT_RUN (Offline simulation mode; no live containers, networks, or volumes created)`
- **Shell Script Syntax Validation:** `NOT_RUN_BY_COLLECTOR`
- **Fail-Closed Adapter Deletion:** `NOT_RUN_BY_COLLECTOR`

---

## 6. Docker Permission Guidance

- **Authorized Sudo Execution:** An authorized operator with sudo privileges can execute:
  `USE_SUDO=1 bash tests/integration/openwebui_cve_2026_28788/scripts/preflight.sh --use-sudo`
  `sudo docker compose -f tests/integration/openwebui_cve_2026_28788/compose.yaml up -d`
- **Rootless Docker:** Set up rootless dockerd via `dockerd-rootless-setuptool.sh install`.
- **Security Notice:** Do NOT run `chmod 666 /var/run/docker.sock` and do NOT unconditionally grant permanent group membership without security authorization.
"""
    (run_dir / "summary.md").write_text(summary_md, encoding="utf-8")

    # 11. Generate Cryptographic SHA256SUMS.txt
    print("Computing cryptographic SHA256 checksums...")
    all_files = sorted([p for p in run_dir.iterdir() if p.is_file() and p.name != "SHA256SUMS.txt"])
    checksum_lines = []
    for f in all_files:
        csum = sha256_file(f)
        checksum_lines.append(f"{csum}  {f.name}")
    csum_manifest = run_dir / "SHA256SUMS.txt"
    csum_manifest.write_text("\n".join(checksum_lines) + "\n", encoding="utf-8")

    # Verify checksums immediately inside run_dir
    res = subprocess.run(
        ["sha256sum", "-c", "SHA256SUMS.txt"],
        cwd=run_dir,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        check=False,
    )
    if res.returncode != 0:
        print(f"Checksum verification failed:\n{res.stdout}")
        sys.exit(1)
    print("  ✓ Cryptographic SHA256SUMS.txt verified successfully.")

    print(f"\n✓ Evidence collection complete. Saved to: {run_dir}")
    for f in run_dir.iterdir():
        print(f"  - {f.name}")


if __name__ == "__main__":
    main()
