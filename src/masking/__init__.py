"""Resource-identifier masking for outbound escalations.

The agent escalates critical findings to GitHub Issues. When the target repo is
public, raw resource identifiers (bucket names, ARNs, account IDs, security-group
IDs, etc.) must not be published. This module replaces those identifiers with
stable, non-reversible aliases so issues stay correlatable without leaking names.

Aliases are deterministic: the same identifier always maps to the same alias, so
multiple findings against one resource line up. Set the ``MASK_SALT`` environment
variable to make aliases unguessable across runs (recommended for public repos).
"""

from __future__ import annotations

import hashlib
import os
import re

# Optional salt — without it, aliases are stable but a determined attacker with a
# known list of candidate names could brute-force the hash. Set MASK_SALT to a
# secret value when escalating to a public repo.
_SALT = os.environ.get("MASK_SALT", "")

# AWS account ID: exactly 12 digits as a standalone token.
_ACCOUNT_RE = re.compile(r"\b\d{12}\b")

# Common AWS resource ID prefixes (sg-, i-, vol-, ami-, …) followed by 8–17 hex.
_RESOURCE_ID_RE = re.compile(
    r"\b(sg|i|vol|eni|ami|snap|subnet|vpc|rtb|igw|nat|acl|fs|db|lt)-[0-9a-f]{8,17}\b"
)

# IAM access key IDs.
_ACCESS_KEY_RE = re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b")


def _alias(value: str, prefix: str = "redacted") -> str:
    """Return a stable, non-reversible alias for an identifier."""
    digest = hashlib.sha256((_SALT + value).encode("utf-8")).hexdigest()[:8]
    return f"<{prefix}:{digest}>"


def mask_text(text: str, names: tuple[str, ...] | list[str] = ()) -> str:
    """Mask resource identifiers in ``text``.

    ``names`` is a collection of known resource-specific strings (e.g. a bucket
    name and its ARN) that should be masked exactly. Generic AWS identifiers
    (account IDs, sg-/i-/vol- style IDs, access key IDs) are masked by pattern.
    Structural skeletons are preserved, e.g. ``arn:aws:s3:::my-bucket`` becomes
    ``arn:aws:s3:::<resource:ab12cd34>``.
    """
    if not text:
        return text

    out = text

    # Mask known specific names first, longest-first so a name that is a prefix
    # of another (e.g. "my-bucket" vs "my-bucket-logs") doesn't partially match.
    for name in sorted({n for n in names if n}, key=len, reverse=True):
        out = out.replace(name, _alias(name, "resource"))

    # Generic AWS identifiers. Resource IDs before account IDs so a 12-digit run
    # inside an ID isn't masked separately.
    out = _RESOURCE_ID_RE.sub(lambda m: _alias(m.group(0), m.group(1)), out)
    out = _ACCOUNT_RE.sub(lambda m: _alias(m.group(0), "account"), out)
    out = _ACCESS_KEY_RE.sub(lambda m: _alias(m.group(0), "akid"), out)

    return out
