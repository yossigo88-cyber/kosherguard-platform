"""Export the URL dataset in Apple PIR tooling's input format.

Apple's swift-homomorphic-encryption PIR pipeline
(PIRGenerateDatabase / PIRShardDatabase / PIRProcessDatabase) consumes
a keyword-PIR database in protobuf text format:

    rows {
      keyword: "0"
      value: "000000000000000"
    }

(keyword: string; value: bytes - per the generated schema
apple.swift.homomorphic.encryption.pir.v1.KeywordValuePair /
KeywordPirDatabase and the PIRShardDatabase doc example.)

What this module is: the dataset-side export that Apple's own Swift
executables process into the servable PIR database. What it is NOT:
the PIR query service itself - the private query path is Apple's Swift
PIR service behind the OHTTP gateway/relay, and reimplementing the
homomorphic-encryption protocol in Python would be invented
cryptography, which this project forbids. The export is the buildable,
verifiable artifact; the service binary is deployment.

Verdict encoding in `value`: "block" or "allow", then ":<category>".
Keywords are normalized (lowercased, no trailing dot).
"""

from __future__ import annotations

from .dataset import URLRule


def _escape_text_string(raw: str) -> str:
    """Protobuf text-format string escaping."""
    out = []
    for ch in raw:
        code = ord(ch)
        if ch == '"':
            out.append('\\"')
        elif ch == "\\":
            out.append("\\\\")
        elif ch == "\n":
            out.append("\\n")
        elif ch == "\r":
            out.append("\\r")
        elif ch == "\t":
            out.append("\\t")
        elif 0x20 <= code < 0x7F:
            out.append(ch)
        else:
            for byte in ch.encode("utf-8"):
                out.append(f"\\{byte:03o}")
    return "".join(out)


def normalize_keyword(url: str) -> str:
    return url.strip().lower().rstrip(".")


def encode_value(rule: URLRule) -> str:
    if rule.verdict not in ("block", "allow"):
        raise ValueError(f"unknown verdict: {rule.verdict!r}")
    return f"{rule.verdict}:{rule.category}" if rule.category \
        else rule.verdict


def export_textpb(rules: list[URLRule]) -> str:
    """Serialize rules to Apple's keyword-PIR textpb input format."""
    chunks = []
    for rule in rules:
        keyword = normalize_keyword(rule.url)
        if not keyword:
            raise ValueError("empty keyword")
        value = encode_value(rule)
        chunks.append(
            'rows {\n'
            f'  keyword: "{_escape_text_string(keyword)}"\n'
            f'  value: "{_escape_text_string(value)}"\n'
            '}\n')
    return "".join(chunks)


def parse_textpb(text: str) -> list[tuple[str, str]]:
    """Minimal reader for the exact subset we emit (round-trip tests
    and verification tooling - not a general textpb parser)."""
    import re
    rows = []
    for match in re.finditer(
            r'rows \{\s*keyword: "((?:[^"\\]|\\.)*)"\s*'
            r'value: "((?:[^"\\]|\\.)*)"\s*\}', text):
        rows.append((match.group(1), match.group(2)))
    return rows


# Apple's NEURLFilter data format (NEURLFilterDataFormat.md in the
# pinned apple/pir-service-example, bbb2153): "If an entry is found
# matching the URL key, it already indicates a match. So the value for
# the record is simply set to the integer 1 serving as place holder."
DEVICE_VALUE_PLACEHOLDER = "1"

# Provenance binding for the device pipeline: ONLY output carrying
# this first-line marker may be processed for the device dataset
# (deploy/pir/prepare-dataset.sh refuses anything else, and the
# interop workflow asserts it). The generic export_textpb output must
# never reach a device: its allow rows would BLOCK the allowed sites
# under presence semantics. The marker is a protobuf-text comment
# (SwiftProtobuf text format accepts `#` comments; the interop CI
# exercises Apple's real PIRProcessDatabase parser on marked output).
DEVICE_EXPORT_MARKER = (
    "# kosherguard-device-export-v1: block-only presence rows for "
    "NEURLFilter; value is Apple's ignored placeholder")


def device_keyword(url: str) -> str:
    """The canonical DEVICE dataset key for a rule URL: normalized
    (lowercase, no trailing dot) and www-stripped, because Apple's
    default ParsingConfiguration lowercases and strips the `www`
    subdomain from requested URLs (init docs, fetched 2026-11-17).
    A www-prefixed or differently-cased key would be a dead row."""
    keyword = normalize_keyword(url)
    if not keyword:
        raise ValueError("empty keyword")
    if keyword.startswith("www."):
        keyword = keyword[len("www."):]
    return keyword


def _strict_domain_ancestors(host: str) -> list[str]:
    """Every strict domain ancestor: a.b.example.com -> [b.example.com,
    example.com, com]. Label-based, NOT public-suffix aware (the PSL
    is out of scope; a block of an effective TLD simply conflicts
    loudly with every allow beneath it)."""
    parts = host.split(".")
    return [".".join(parts[i:]) for i in range(1, len(parts))]


def device_block_keywords(rules: list[URLRule]) -> list[str]:
    """The exact key set the DEVICE (NEURLFilter) dataset may contain.

    Grounded in Apple's documentation (fetched 2026-11-17): the
    dataset has NO allow concept (presence means block; the value is
    a placeholder), and the default ParsingConfiguration makes the
    system enumerate ALL sub-URL combinations walking the domain and
    path hierarchies. Consequences applied here:

    - exact allow-beats-block: a key with ANY allow rule is excluded
      even when a block rule also names it (mirrors the supervised
      engine's explicit-allow-beats-block order at exact-key level);
    - ANCESTOR CONFLICTS ARE REFUSED: a block key that is a strict
      domain ancestor of an allowed key cannot be faithfully
      expressed - enumeration means the allowed host's request also
      matches the ancestor key, and there is no negative verdict to
      carve the exception. Silently emitting the block would block an
      explicitly allowed site; silently dropping it would weaken the
      policy. Refuse loudly and name both keys: the control plane
      must enumerate the blocked hosts individually (excluding the
      allowed subtree) instead of blocking the ancestor.

    Invalid rows raise (unknown verdict, empty keyword): an export
    that silently drops a malformed BLOCK rule would silently weaken
    filtering.
    """
    allowed: set[str] = set()
    blocked: set[str] = set()
    for rule in rules:
        if rule.verdict not in ("block", "allow"):
            raise ValueError(f"unknown verdict: {rule.verdict!r}")
        keyword = device_keyword(rule.url)
        if rule.verdict == "allow":
            allowed.add(keyword)
        else:
            blocked.add(keyword)
    effective = blocked - allowed
    for allow_key in sorted(allowed):
        for ancestor in _strict_domain_ancestors(allow_key):
            if ancestor in effective:
                raise ValueError(
                    "unexpressible exception on the URL Filter lane: "
                    f"allow {allow_key!r} sits under block "
                    f"{ancestor!r}; Apple's enumerated matching has no "
                    "allow verdict, so enumerate the blocked hosts "
                    "individually (excluding the allowed subtree) "
                    "instead of blocking the ancestor")
    return sorted(effective)


def export_device_textpb(rules: list[URLRule]) -> str:
    """Serialize the DEVICE (NEURLFilter) dataset: BLOCK ROWS ONLY.

    Presence semantics: on device, a keyword PRESENT in this dataset is
    BLOCKED - the system ignores the value (Apple's placeholder "1").
    An allow row emitted here would therefore BLOCK the allowed site.
    The key set comes from device_block_keywords (exact allow
    precedence, www canonicalization, ancestor-conflict refusal). This
    export additionally collapses duplicates and emits Apple's
    placeholder value, not a verdict string: carrying
    "block:<category>" here would pretend the value has on-device
    meaning it does not have.
    """
    rows = device_block_keywords(rules)
    return DEVICE_EXPORT_MARKER + "\n" + "".join(
        'rows {\n'
        f'  keyword: "{_escape_text_string(keyword)}"\n'
        f'  value: "{DEVICE_VALUE_PLACEHOLDER}"\n'
        '}\n' for keyword in rows)
