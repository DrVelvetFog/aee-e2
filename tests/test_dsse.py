"""DSSE Pre-Authentication Encoding and payload decoding."""

import base64
import unittest

from aee.dsse import DSSEError, decode_payload, pae, pae_for_record


class TestPAE(unittest.TestCase):
    def test_known_shape(self):
        self.assertEqual(
            pae("application/vnd.in-toto+json", b"hello"),
            b"DSSEv1 28 application/vnd.in-toto+json 5 hello",
        )

    def test_empty_body_keeps_the_trailing_separator(self):
        # Length zero still costs a space; dropping it would make PAE ambiguous.
        self.assertEqual(pae("test", b""), b"DSSEv1 4 test 0 ")

    def test_lengths_count_bytes_not_characters(self):
        # U+00E9 is one character and two UTF-8 bytes.
        self.assertEqual(pae("é", b""), b"DSSEv1 2 \xc3\xa9 0 ")
        self.assertEqual(pae("t", "é".encode("utf-8")), b"DSSEv1 1 t 2 \xc3\xa9")

    def test_body_must_already_be_bytes(self):
        with self.assertRaises(DSSEError):
            pae("t", "not bytes")

    def test_separators_cannot_be_forged_from_the_payload_type(self):
        # A type containing a space still yields an unambiguous encoding,
        # because the lengths are authoritative, not the separators.
        a = pae("a b", b"c")
        b = pae("a", b"b c")
        self.assertNotEqual(a, b)


class TestDecodePayload(unittest.TestCase):
    def test_round_trip(self):
        body = b"\x00\x01binary\xff"
        self.assertEqual(
            decode_payload(base64.b64encode(body).decode("ascii")), body
        )

    def test_rejects_characters_outside_the_alphabet(self):
        with self.assertRaises(DSSEError):
            decode_payload("aGVsbG8*")

    def test_rejects_embedded_whitespace(self):
        with self.assertRaises(DSSEError):
            decode_payload("aGVs bG8=")

    def test_rejects_non_string(self):
        with self.assertRaises(DSSEError):
            decode_payload(b"aGVsbG8=")


class TestPAEForRecord(unittest.TestCase):
    def record(self, body=b"{}", payload_type="application/vnd.example+json"):
        return {
            "payload": base64.b64encode(body).decode("ascii"),
            "payloadType": payload_type,
            "signatures": [{"keyid": "00", "sig": "AA=="}],
        }

    def test_uses_the_decoded_body(self):
        rec = self.record(b"{}")
        self.assertEqual(
            pae_for_record(rec), pae("application/vnd.example+json", b"{}")
        )

    def test_missing_members_are_refused(self):
        for missing in ("payload", "payloadType"):
            rec = self.record()
            del rec[missing]
            with self.assertRaises(DSSEError):
                pae_for_record(rec)

    def test_payload_type_must_be_a_string(self):
        rec = self.record()
        rec["payloadType"] = 7
        with self.assertRaises(DSSEError):
            pae_for_record(rec)

    def test_record_must_be_an_object(self):
        with self.assertRaises(DSSEError):
            pae_for_record(["not", "an", "object"])


if __name__ == "__main__":
    unittest.main()
