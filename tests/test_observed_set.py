"""The aeeObservedSet commitment, composed from the other primitives."""

import hashlib
import unittest

from aee.merkle import leaf_hash
from aee.observed_set import (
    OBSERVED_KINDS,
    observed_set_from_leaf_hexes,
    observed_set_from_paes,
)


def expected_over(hexes):
    """Independent construction of the commitment for all-hex members.

    Lowercase hex needs no JCS escaping and sorts identically under code point
    and UTF-16 code unit, so the canonical array can be written out directly
    here rather than borrowing the canonicaliser under test.
    """
    body = "[" + ",".join('"%s"' % x for x in sorted(hexes)) + "]"
    return hashlib.sha256(body.encode("utf-8")).hexdigest()


class TestCommitment(unittest.TestCase):
    def test_single_member(self):
        one = leaf_hash(b"pae-a").hex()
        self.assertEqual(
            observed_set_from_leaf_hexes([one]), expected_over({one})
        )

    def test_several_members(self):
        hexes = [leaf_hash(b"pae-%d" % i).hex() for i in range(5)]
        self.assertEqual(
            observed_set_from_leaf_hexes(hexes), expected_over(set(hexes))
        )

    def test_result_is_lowercase_64_hex(self):
        value = observed_set_from_paes([b"pae-a", b"pae-b"])
        self.assertEqual(len(value), 64)
        self.assertEqual(value, value.lower())
        int(value, 16)

    def test_input_order_does_not_matter(self):
        # The array is sorted before canonicalisation, so emission order of the
        # records cannot move the commitment.
        hexes = [leaf_hash(b"pae-%d" % i).hex() for i in range(4)]
        self.assertEqual(
            observed_set_from_leaf_hexes(hexes),
            observed_set_from_leaf_hexes(list(reversed(hexes))),
        )

    def test_duplicates_collapse(self):
        # "the duplicate-free array" -- a repeated leaf contributes once.
        one = leaf_hash(b"pae-a").hex()
        self.assertEqual(
            observed_set_from_leaf_hexes([one, one, one]),
            observed_set_from_leaf_hexes([one]),
        )

    def test_an_empty_set_still_commits(self):
        # A run that emitted nothing commits to the empty array, which is a
        # claim, not an absence. sha256 of "[]".
        self.assertEqual(
            observed_set_from_leaf_hexes([]),
            hashlib.sha256(b"[]").hexdigest(),
        )

    def test_dropping_a_record_moves_the_value(self):
        hexes = [leaf_hash(b"pae-%d" % i).hex() for i in range(3)]
        self.assertNotEqual(
            observed_set_from_leaf_hexes(hexes),
            observed_set_from_leaf_hexes(hexes[:-1]),
        )

    def test_leaf_construction_matches_batch_root(self):
        # "the same leaf construction batchRoot uses"
        self.assertEqual(
            observed_set_from_paes([b"x"]),
            observed_set_from_leaf_hexes([leaf_hash(b"x").hex()]),
        )

    def test_committed_kinds_are_exactly_two(self):
        self.assertEqual(OBSERVED_KINDS, ("interception", "examination"))


if __name__ == "__main__":
    unittest.main()
