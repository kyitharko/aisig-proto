#!/usr/bin/env python3
"""Redact secrets from n8n execution exports before they are committed/published.

n8n execution exports can carry a `data.resumeToken` and, in general, credential/token fields.
These are secrets and must never enter a publishable artifact. This sanitizer recursively removes
any object key that names a token, credential, secret, password, cookie, or authorization value,
rewrites the file in place (stable 2-space JSON), and reports *paths and counts only* — never the
redacted values. It is idempotent: running it on an already-clean file changes nothing.

Usage:
    python3 scripts/sanitize_n8n_export.py <file-or-dir> [<file-or-dir> ...]
    # default target when no argument is given:
    python3 scripts/sanitize_n8n_export.py results/model_demo

Exit code 0 always (it fixes files); use tests/model_demo_gate.rs as the blocking gate.
"""
import json
import os
import sys

# Keys are matched separator-insensitively: the name is lowercased and its '-', '_' and spaces
# are removed before comparison, so "api-key", "api_key" and "apikey" all match, as do header
# forms such as "Set-Cookie", "Proxy-Authorization" and "WWW-Authenticate". A normalized name is
# stripped if it is in SENSITIVE_EXACT or ends with one of SENSITIVE_SUFFIX.
SENSITIVE_EXACT = {
    "resumetoken", "token", "accesstoken", "refreshtoken", "sessiontoken", "oauthtokendata",
    "credential", "credentials", "secret", "secrets", "password", "passwd",
    "apikey", "xapikey", "authorization", "proxyauthorization", "wwwauthenticate",
    "cookie", "setcookie", "privatekey", "bearer",
}
SENSITIVE_SUFFIX = ("token", "secret", "password", "apikey", "credential", "cookie", "authorization")


def _norm(key: str) -> str:
    return key.lower().replace("-", "").replace("_", "").replace(" ", "")


def is_sensitive(key: str) -> bool:
    k = _norm(key)
    return k in SENSITIVE_EXACT or k.endswith(SENSITIVE_SUFFIX)


def sanitize(node, path, removed):
    if isinstance(node, dict):
        out = {}
        for k, v in node.items():
            if is_sensitive(k):
                removed.append(f"{path}.{k}")
                continue
            out[k] = sanitize(v, f"{path}.{k}", removed)
        return out
    if isinstance(node, list):
        return [sanitize(v, f"{path}[{i}]", removed) for i, v in enumerate(node)]
    return node


def sanitize_file(fp) -> int:
    with open(fp, "r", encoding="utf-8") as fh:
        data = json.load(fh)
    removed = []
    cleaned = sanitize(data, "", removed)
    if removed:
        with open(fp, "w", encoding="utf-8") as fh:
            json.dump(cleaned, fh, indent=2)
            fh.write("\n")
        print(f"sanitized {fp}: removed {len(removed)} sensitive key(s) at {sorted(set(removed))}")
    else:
        print(f"clean     {fp}: no sensitive keys")
    return len(removed)


def iter_targets(args):
    for a in args:
        if os.path.isdir(a):
            for name in sorted(os.listdir(a)):
                if name.endswith(".json"):
                    yield os.path.join(a, name)
        else:
            yield a


def main():
    args = sys.argv[1:] or ["results/model_demo"]
    total = 0
    for fp in iter_targets(args):
        total += sanitize_file(fp)
    print(f"done: {total} sensitive key(s) removed in total (values were never printed)")


if __name__ == "__main__":
    main()
