"""Canonical network-binding addresses for the KosherGuard device registry
(Stage 11A).

Every device-registry binding value is normalized to exactly one canonical
form BEFORE it is checked for duplicates, stored, or published. This module
is the single implementation of that normalization: the dashboard calls it
at write time and the filtering engine calls it at lookup time (Stage 11C),
so a binding can never exist in two spellings and duplicate detection is a
plain string comparison. See docs/reviews/STAGE_11_TECHNICAL_PLAN.md,
section 6.2, whose rules this module implements exactly.

A binding value is a NETWORK/GROUP routing hint ("queries from this address
or prefix should receive this registry entry's policy"). It is never a
device identity, never authentication, and never proof that a specific
physical device sent a query.
"""

from __future__ import annotations

import ipaddress
import re

# The association kinds Stage 11A supports. `token_hash` exists in the
# database schema as a RESERVED kind for a future authenticated-identity
# stage; it is deliberately not canonicalizable here because Stage 11A
# never issues, stores, or authenticates device tokens.
BINDING_KINDS = ("ipv4", "ipv6_prefix")

# kind -> identity class, the ONLY permitted pairs (also enforced by the
# database CHECK constraint; see dashboard db.py SCHEMA_STAGE11).
IDENTITY_CLASS_FOR_KIND = {
    "ipv4": "network_binding",
    "ipv6_prefix": "network_binding",
    "token_hash": "credential",
}

_PREFIX_LEN_RE = re.compile(r"^[0-9]+$")

# An IPv6 address whose top 96 bits are all zero covers the unspecified
# address (::), the loopback (::1), and the entire deprecated
# IPv4-compatible block ::/96 (RFC 4291 section 2.5.5.1).
_IPV4_COMPATIBLE_TOP_BITS = 1 << 32


class BindingValidationError(ValueError):
    """A binding value is malformed, ambiguous, or of a disallowed class.

    The message names the field and the reason; rejected input is never
    silently repaired.
    """


def identity_class_for_kind(kind: str) -> str:
    """The identity class the server derives for an association kind.

    Clients never supply identity_class; it is always derived here.
    """
    try:
        return IDENTITY_CLASS_FOR_KIND[kind]
    except KeyError:
        raise BindingValidationError(
            f"kind: unknown association kind {kind!r} "
            f"(valid kinds: {sorted(IDENTITY_CLASS_FOR_KIND)})"
        )


def _require_plain_string(value, field: str) -> str:
    if not isinstance(value, str):
        raise BindingValidationError(
            f"{field}: must be a string, got {type(value).__name__}")
    if not value:
        raise BindingValidationError(f"{field}: must not be empty")
    if value != value.strip():
        raise BindingValidationError(
            f"{field}: must not have surrounding whitespace")
    return value


def canonicalize_ipv4(value) -> str:
    """Canonical dotted-quad form of an exact IPv4 address binding.

    The strict stdlib parser rejects leading zeros ("192.168.001.50"),
    non-dotted forms (single integers, hex, octal), out-of-range octets,
    prefix notation, and IPv6 input; nothing is silently repaired.
    """
    value = _require_plain_string(value, "value")
    try:
        address = ipaddress.IPv4Address(value)
    except ipaddress.AddressValueError as exc:
        raise BindingValidationError(f"value: invalid IPv4 address {value!r} ({exc})")
    return str(address)


def canonicalize_ipv6_prefix(value) -> str:
    """Canonical form of an IPv6 /64 network/group binding.

    Only strict /64 network addresses are accepted: the prefix length must
    be exactly 64 and the address part must be the network address (strict
    parsing rejects host bits, so "2001:db8::1/64" is rejected and the
    administrator writes "2001:db8::/64"). The result is the stdlib
    compressed lowercase form ("2001:db8::/64").

    Rejected, with the reason named:
    - any prefix length other than /64 (no /128 device bindings, no /48);
    - host bits set under a /64;
    - zone IDs ("fe80::%eth0/64");
    - IPv4-mapped forms (RFC 4291 2.5.5.2: "::ffff:192.0.2.1" and the hex
      spelling "::ffff:c000:201") in any prefix notation;
    - the IPv4-compatible class (deprecated RFC 4291 2.5.5.1): any address
      whose top 96 bits are zero, which under the exact-/64 rule is
      exactly the network "::/64" - rejected in every spelling ("::/64",
      "0:0:0:0:0:0:0:0/64", "::0.0.0.0/64") because it contains the
      unspecified address, the loopback, and the entire deprecated
      IPv4-compatible block. This also catches "::1/64" and
      "::192.0.2.1/64" before strict parsing would.

    IPv4 space therefore has exactly one representation (kind "ipv4") and
    cannot be duplicated through the IPv6 kind. The NAT64 well-known
    prefix "64:ff9b::/64" is NOT IPv4-compatible (its top 96 bits are
    nonzero) and stays acceptable as an ordinary /64 group binding.
    """
    value = _require_plain_string(value, "value")
    if "%" in value:
        raise BindingValidationError(
            f"value: zone IDs are not supported in IPv6 bindings ({value!r})")
    parts = value.split("/")
    if len(parts) != 2:
        raise BindingValidationError(
            f"value: an IPv6 binding must be a prefix in \"address/64\" form, "
            f"got {value!r}")
    addr_text, prefix_text = parts
    try:
        address = ipaddress.IPv6Address(addr_text)
    except ipaddress.AddressValueError as exc:
        raise BindingValidationError(
            f"value: invalid IPv6 address {addr_text!r} ({exc})")
    if address.ipv4_mapped is not None:
        raise BindingValidationError(
            f"value: IPv4-mapped IPv6 addresses ({value!r}) are not valid "
            "ipv6_prefix bindings; register the address as an 'ipv4' binding")
    if int(address) < _IPV4_COMPATIBLE_TOP_BITS:
        raise BindingValidationError(
            f"value: {value!r} is in the deprecated IPv4-compatible/unspecified "
            "IPv6 range (top 96 bits all zero) and cannot be a binding; "
            "IPv4 space is represented only by 'ipv4' bindings")
    if not _PREFIX_LEN_RE.match(prefix_text):
        raise BindingValidationError(
            f"value: invalid prefix length {prefix_text!r} (must be exactly 64)")
    if int(prefix_text) != 64:
        raise BindingValidationError(
            f"value: prefix length must be exactly /64 for an IPv6 network/group "
            f"binding, got /{prefix_text} (per-device /128 bindings are not "
            "supported)")
    try:
        network = ipaddress.IPv6Network(value, strict=True)
    except ValueError:
        raise BindingValidationError(
            f"value: {value!r} has host bits set; an ipv6_prefix binding must "
            f"be the network address of its /64 (write "
            f"\"{ipaddress.IPv6Network(value, strict=False)}\")")
    return str(network)


def canonicalize_binding(kind, value) -> str:
    """The canonical stored form of one association value.

    Raises BindingValidationError for an unknown kind, a reserved kind
    (token_hash: reserved schema kind only in Stage 11A), or a malformed
    value. Only canonical strings are ever stored, so the database's
    partial unique index on (kind, value) IS the canonical duplicate
    check.
    """
    identity_class_for_kind(kind)  # validates the kind itself
    if kind == "ipv4":
        return canonicalize_ipv4(value)
    if kind == "ipv6_prefix":
        return canonicalize_ipv6_prefix(value)
    # token_hash is a reserved kind: Stage 11A issues, stores, and
    # authenticates no device tokens, so there is nothing to canonicalize.
    raise BindingValidationError(
        f"kind: {kind!r} is a reserved credential kind for a future "
        "authenticated-identity stage; device tokens cannot be registered "
        "in Stage 11A")


def canonical_source_key(source_address) -> str:
    """The canonical binding-lookup key for an observed source address.

    An IPv4 source maps to its dotted-quad key; an IPv6 source maps to the
    canonical string of its /64 network (the group-binding key). Used by
    the engine's Stage 11C lookup path so lookups always match stored
    canonical bindings with a plain string dict lookup.

    Two observed-source spellings are normalized so one network identity
    always has exactly one lookup key (the same single-representation
    rule as section 6.2):

    - IPv4-mapped IPv6 forms ("::ffff:192.168.1.50", as a dual-stack
      AF_INET6 socket may report an IPv4 client) map to the IPv4 key -
      the same identity cannot dodge or miss its IPv4 binding by
      arriving in mapped spelling.
    - IPv6 zone/scope identifiers ("fe80::1%eth0", or the scope of an
      AF_INET6 socket-address tuple's host) are stripped: a scope marks
      the receiving interface, not a different network identity, so a
      scoped spelling of an address resolves to the same /64 binding as
      the bare address.
    """
    address = ipaddress.ip_address(source_address)
    if isinstance(address, ipaddress.IPv4Address):
        return f"ipv4:{address}"
    if address.ipv4_mapped is not None:
        return f"ipv4:{address.ipv4_mapped}"
    if getattr(address, "scope_id", None) is not None:
        address = ipaddress.IPv6Address(int(address))
    network = ipaddress.IPv6Network(f"{address}/64", strict=False)
    return f"ipv6:{network}"
