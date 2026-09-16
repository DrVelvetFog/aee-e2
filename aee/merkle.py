"""RFC 6962 Merkle root over observation records, as ``batchRoot`` defines it.

Spec basis (head 25ac8581), ``batchRoot``: "An RFC 6962 Merkle root over the
observation records, SHA-256, with domain-separated hashing: each leaf is
``H(0x00 || the record's DSSE PAE bytes)``, each internal node is
``H(0x01 || left || right)``, the tree built by the RFC 6962 recursive split
(never by duplicating a trailing node to pad the leaf count), leaves in
``observationRecords`` array order, a single-record tree's root its leaf hash,
and an empty array with no root."

"Two byte-identical entries in ``observationRecords`` make the attestation
invalid: a record's canonical identity is its leaf hash." Duplicate leaves are
therefore refused here rather than hashed, so the refusal cannot be reached by
a caller that forgot to check.
"""

import hashlib

from .dsse import pae_for_record

__all__ = ["leaf_hash", "node_hash", "merkle_root", "root_for_records", "MerkleError"]

LEAF_PREFIX = b"\x00"
NODE_PREFIX = b"\x01"


class MerkleError(ValueError):
    """A record set with no well-defined root."""


def _sha256(data):
    return hashlib.sha256(data).digest()


def leaf_hash(pae_bytes):
    """``H(0x00 || PAE bytes)``."""
    return _sha256(LEAF_PREFIX + pae_bytes)


def node_hash(left, right):
    """``H(0x01 || left || right)``."""
    return _sha256(NODE_PREFIX + left + right)


def _split(n):
    """Largest power of two strictly less than ``n`` (RFC 6962's k)."""
    k = 1
    while k * 2 < n:
        k *= 2
    return k


def merkle_root(leaves):
    """Root over already-computed leaf hashes, in order.

    Returns ``None`` for an empty list: an empty array has no root, which is a
    different statement from the hash of nothing.
    """
    n = len(leaves)
    if n == 0:
        return None
    if n == 1:
        return leaves[0]
    k = _split(n)
    return node_hash(merkle_root(leaves[:k]), merkle_root(leaves[k:]))


def root_for_records(records):
    """Lowercase 64-hex ``batchRoot`` over observation records in array order.

    ``None`` when ``records`` is empty, matching "an empty array with no root".
    """
    if not records:
        return None
    paes = [pae_for_record(r) for r in records]
    seen = {}
    for index, raw in enumerate(paes):
        if raw in seen:
            raise MerkleError(
                "observationRecords[%d] is byte-identical to [%d]; a record's "
                "canonical identity is its leaf hash" % (index, seen[raw])
            )
        seen[raw] = index
    return merkle_root([leaf_hash(p) for p in paes]).hex()
