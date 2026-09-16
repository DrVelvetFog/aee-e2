"""``aeeObservedSet``: the seal's commitment to the set the substrate emitted.

Spec basis (head 25ac8581): "the lowercase 64-hex SHA-256 of the RFC 8785
canonicalization of the duplicate-free array, sorted ascending by UTF-16 code
unit, of the lowercase 64-hex leaf hashes of every ``interception`` and
``examination`` record the substrate emitted for this run, where a leaf hash is
``H(0x00 || the record's DSSE PAE bytes)``, the same leaf construction
``batchRoot`` uses."

Reading it in the order the sentence builds: leaf-hash each qualifying record,
render lowercase hex, drop duplicates, sort by UTF-16 code unit, canonicalise
that array of strings, SHA-256 it, render lowercase hex.

Selecting the qualifying records means reading ``aeeKind`` out of each record's
payload, and a payload may only be read once it has passed the strict I-JSON
profile Prerequisites states. That reader is a separate piece; until it exists
the selection is the caller's, so the computation here stays pure and is driven
by pre-attributed inputs.
"""

import hashlib

from .jcs import canonicalize, sort_utf16
from .merkle import leaf_hash

__all__ = ["OBSERVED_KINDS", "observed_set_from_paes", "observed_set_from_leaf_hexes"]

#: The two record kinds the seal commits to. The spec names them explicitly and
#: the set is closed: a run-level ``arming`` or ``sealed`` record is not a member.
OBSERVED_KINDS = ("interception", "examination")


def observed_set_from_leaf_hexes(leaf_hexes):
    """Commitment over already-rendered lowercase 64-hex leaf hashes."""
    unique = sort_utf16(set(leaf_hexes))
    return hashlib.sha256(canonicalize(unique)).hexdigest()


def observed_set_from_paes(pae_list):
    """Commitment over the PAE bytes of the qualifying records."""
    return observed_set_from_leaf_hexes(leaf_hash(p).hex() for p in pae_list)
