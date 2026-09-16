"""RFC 6962 tree shape, domain separation, and the no-padding rule."""

import hashlib
import unittest

from aee.merkle import MerkleError, leaf_hash, merkle_root, node_hash, root_for_records


def h(data):
    return hashlib.sha256(data).digest()


def leaves(n):
    return [leaf_hash(b"record-%d" % i) for i in range(n)]


class TestHashing(unittest.TestCase):
    def test_leaf_is_domain_separated_with_0x00(self):
        self.assertEqual(leaf_hash(b"x"), h(b"\x00x"))

    def test_node_is_domain_separated_with_0x01(self):
        left, right = h(b"l"), h(b"r")
        self.assertEqual(node_hash(left, right), h(b"\x01" + left + right))

    def test_a_leaf_can_never_collide_with_an_internal_node(self):
        # The whole point of the prefixes: the same bytes hashed as a leaf and
        # as a node are different values.
        self.assertNotEqual(leaf_hash(b""), h(b"\x01"))


class TestTreeShape(unittest.TestCase):
    def test_empty_array_has_no_root(self):
        # "an empty array with no root" -- distinct from the hash of nothing.
        self.assertIsNone(merkle_root([]))
        self.assertNotEqual(merkle_root([]), h(b""))

    def test_single_record_tree_is_its_leaf(self):
        only = leaves(1)
        self.assertEqual(merkle_root(only), only[0])

    def test_two_leaves(self):
        lv = leaves(2)
        self.assertEqual(merkle_root(lv), node_hash(lv[0], lv[1]))

    def test_three_leaves_split_two_and_one(self):
        # k is the largest power of two strictly less than n, so n=3 splits 2|1.
        lv = leaves(3)
        self.assertEqual(
            merkle_root(lv), node_hash(node_hash(lv[0], lv[1]), lv[2])
        )

    def test_four_leaves_split_evenly(self):
        lv = leaves(4)
        self.assertEqual(
            merkle_root(lv),
            node_hash(node_hash(lv[0], lv[1]), node_hash(lv[2], lv[3])),
        )

    def test_five_leaves_split_four_and_one(self):
        lv = leaves(5)
        left = node_hash(node_hash(lv[0], lv[1]), node_hash(lv[2], lv[3]))
        self.assertEqual(merkle_root(lv), node_hash(left, lv[4]))

    def test_six_leaves_split_four_and_two(self):
        lv = leaves(6)
        left = node_hash(node_hash(lv[0], lv[1]), node_hash(lv[2], lv[3]))
        self.assertEqual(merkle_root(lv), node_hash(left, node_hash(lv[4], lv[5])))

    def test_trailing_node_is_never_duplicated_to_pad(self):
        # The negative control for "never by duplicating a trailing node to pad
        # the leaf count". A padding implementation would balance n=3 by
        # repeating the last leaf; that must not be this root.
        lv = leaves(3)
        padded = node_hash(node_hash(lv[0], lv[1]), node_hash(lv[2], lv[2]))
        self.assertNotEqual(merkle_root(lv), padded)

    def test_order_is_significant(self):
        lv = leaves(3)
        self.assertNotEqual(merkle_root(lv), merkle_root(list(reversed(lv))))


def envelope(body, payload_type="application/vnd.example+json"):
    import base64

    return {
        "payload": base64.b64encode(body).decode("ascii"),
        "payloadType": payload_type,
        "signatures": [{"keyid": "00", "sig": "AA=="}],
    }


class TestRootForRecords(unittest.TestCase):
    def test_empty_records_have_no_root(self):
        self.assertIsNone(root_for_records([]))
        self.assertIsNone(root_for_records(None))

    def test_root_is_lowercase_64_hex(self):
        root = root_for_records([envelope(b"a"), envelope(b"b")])
        self.assertEqual(len(root), 64)
        self.assertEqual(root, root.lower())
        int(root, 16)

    def test_byte_identical_entries_are_refused(self):
        # "Two byte-identical entries in observationRecords make the
        # attestation invalid."
        same = envelope(b"a")
        with self.assertRaises(MerkleError) as caught:
            root_for_records([same, dict(same)])
        self.assertIn("byte-identical", str(caught.exception))

    def test_records_differing_only_in_payload_type_are_not_duplicates(self):
        root = root_for_records(
            [envelope(b"a"), envelope(b"a", "application/vnd.other+json")]
        )
        self.assertEqual(len(root), 64)

    def test_array_order_is_preserved(self):
        a, b = envelope(b"a"), envelope(b"b")
        self.assertNotEqual(root_for_records([a, b]), root_for_records([b, a]))


if __name__ == "__main__":
    unittest.main()
