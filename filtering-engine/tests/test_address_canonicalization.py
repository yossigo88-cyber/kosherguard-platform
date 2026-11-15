"""Tests for the Stage 11A shared binding canonicalizer.

The full plan section 6.2 matrix: equivalent spellings collapse to one
canonical value; malformed, ambiguous, wrong-length, host-bits-set,
zone-ID, IPv4-mapped, and IPv4-compatible inputs are rejected with named
reasons; the NAT64 boundary is pinned; reserved kinds are refused.
"""

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from address_canonicalization import (  # noqa: E402
    BindingValidationError,
    canonicalize_binding,
    canonicalize_ipv4,
    canonicalize_ipv6_prefix,
    canonical_source_key,
    identity_class_for_kind,
)


# -- IPv4 ------------------------------------------------------------

def test_ipv4_canonical_stored_unchanged():
    assert canonicalize_ipv4("192.168.1.50") == "192.168.1.50"
    assert canonicalize_ipv4("10.0.0.1") == "10.0.0.1"


def test_ipv4_leading_zeros_rejected_not_corrected():
    with pytest.raises(BindingValidationError):
        canonicalize_ipv4("192.168.001.50")


@pytest.mark.parametrize("bad", [
    "999.1.1.1",            # out-of-range octet
    "192.168.1",            # too few octets
    "192.168.1.50/24",      # prefix notation not allowed
    "0xC0A80132",           # hex form
    "3232235846",           # single-integer form
    "0300.0250.0001.0062",  # octal-looking form
    "192.168.1.50 ",        # surrounding whitespace
    " 192.168.1.50",
    "",                     # empty
    "2001:db8::1",          # IPv6 input on the IPv4 kind
    "example.com",
])
def test_ipv4_malformed_rejected(bad):
    with pytest.raises(BindingValidationError):
        canonicalize_ipv4(bad)


def test_ipv4_non_string_rejected():
    with pytest.raises(BindingValidationError):
        canonicalize_ipv4(3232235846)
    with pytest.raises(BindingValidationError):
        canonicalize_ipv4(None)


# -- IPv6 /64 group prefixes ------------------------------------------

@pytest.mark.parametrize("spelling", [
    "2001:0DB8:0000:0000:0000:0000:0000:0000/64",
    "2001:DB8::/64",
    "2001:db8:0:0::/64",
    "2001:db8::/64",
])
def test_ipv6_equivalent_spellings_collapse(spelling):
    assert canonicalize_ipv6_prefix(spelling) == "2001:db8::/64"


def test_ipv6_mixed_dotted_nonreserved_canonicalized():
    # Not special-cased: parses unambiguously and stores canonically.
    assert canonicalize_ipv6_prefix("2001:db8::0.0.0.0/64") == "2001:db8::/64"


def test_ipv6_host_bits_set_rejected():
    with pytest.raises(BindingValidationError) as exc:
        canonicalize_ipv6_prefix("2001:db8::1/64")
    assert "host bits" in str(exc.value)


@pytest.mark.parametrize("bad", ["2001:db8::/48", "2001:db8::/128",
                                 "2001:db8::/32", "2001:db8::/64 "])
def test_ipv6_wrong_prefix_length_rejected(bad):
    with pytest.raises(BindingValidationError):
        canonicalize_ipv6_prefix(bad)


def test_ipv6_zone_id_rejected():
    with pytest.raises(BindingValidationError) as exc:
        canonicalize_ipv6_prefix("fe80::%eth0/64")
    assert "zone" in str(exc.value).lower()


def test_ipv6_malformed_rejected():
    with pytest.raises(BindingValidationError):
        canonicalize_ipv6_prefix("2001:::0/64")
    with pytest.raises(BindingValidationError):
        canonicalize_ipv6_prefix("2001:db8::")
    with pytest.raises(BindingValidationError):
        canonicalize_ipv6_prefix("192.168.1.50/64")  # IPv4 input


def test_ipv4_mapped_rejected_mixed_spelling():
    with pytest.raises(BindingValidationError) as exc:
        canonicalize_ipv6_prefix("::ffff:192.0.2.1/64")
    assert "mapped" in str(exc.value).lower()


def test_ipv4_mapped_rejected_hex_spelling():
    with pytest.raises(BindingValidationError) as exc:
        canonicalize_ipv6_prefix("::ffff:c000:201/64")
    assert "mapped" in str(exc.value).lower()


@pytest.mark.parametrize("spelling", [
    "::/64",                # parses cleanly under strict /64 - still rejected
    "0:0:0:0:0:0:0:0/64",
    "::0.0.0.0/64",
])
def test_slash64_rejected_every_spelling(spelling):
    # ::/64 contains the unspecified address, the loopback, and the whole
    # deprecated IPv4-compatible block ::/96.
    with pytest.raises(BindingValidationError):
        canonicalize_ipv6_prefix(spelling)


@pytest.mark.parametrize("spelling", ["::1/64", "::192.0.2.1/64", "::c000:201/64"])
def test_ipv4_compatible_rejected(spelling):
    with pytest.raises(BindingValidationError):
        canonicalize_ipv6_prefix(spelling)


def test_nat64_well_known_prefix_accepted():
    # 64:ff9b::/64 has nonzero top 96 bits: NOT IPv4-compatible.
    assert canonicalize_ipv6_prefix("64:ff9b::/64") == "64:ff9b::/64"


# -- kinds and identity classes ----------------------------------------

def test_kind_dispatch():
    assert canonicalize_binding("ipv4", "10.1.2.3") == "10.1.2.3"
    assert canonicalize_binding("ipv6_prefix", "2001:DB8::/64") == "2001:db8::/64"


def test_token_hash_is_reserved_only():
    with pytest.raises(BindingValidationError) as exc:
        canonicalize_binding("token_hash", "0" * 64)
    assert "reserved" in str(exc.value)


def test_unknown_kind_rejected():
    with pytest.raises(BindingValidationError):
        canonicalize_binding("mac", "aa:bb:cc:dd:ee:ff")


def test_identity_class_derivation():
    assert identity_class_for_kind("ipv4") == "network_binding"
    assert identity_class_for_kind("ipv6_prefix") == "network_binding"
    assert identity_class_for_kind("token_hash") == "credential"
    with pytest.raises(BindingValidationError):
        identity_class_for_kind("hostname")


# -- engine lookup keys (used by Stage 11C) -----------------------------

def test_source_key_ipv4_dotted_quad():
    assert canonical_source_key("192.168.1.50") == "ipv4:192.168.1.50"


def test_source_key_ipv6_maps_into_canonical_slash64():
    assert canonical_source_key("2001:db8:1:2::99") == "ipv6:2001:db8:1:2::/64"
    assert canonical_source_key("2001:DB8:1:2:0:0:0:99") == "ipv6:2001:db8:1:2::/64"
