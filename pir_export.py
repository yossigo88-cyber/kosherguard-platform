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
