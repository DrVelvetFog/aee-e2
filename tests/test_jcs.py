"""RFC 8785 canonicalisation, including the ECMAScript number layout."""

import unittest

from aee.jcs import JCSError, canonicalize, canonicalize_str, sort_utf16, utf16_key


class TestNumbers(unittest.TestCase):
    def test_ecmascript_exponential_thresholds(self):
        # The two boundaries where ECMAScript and Python disagree. Python's repr
        # goes exponential at 1e16; ECMAScript holds positional notation to 1e21.
        self.assertEqual(canonicalize_str(1e20), "100000000000000000000")
        self.assertEqual(canonicalize_str(1e21), "1e+21")
        self.assertEqual(canonicalize_str(1e16), "10000000000000000")

    def test_small_magnitude_boundary(self):
        # Positional down to 1e-6, exponential from 1e-7, with no "+" on a
        # negative exponent and no zero padding.
        self.assertEqual(canonicalize_str(0.000001), "0.000001")
        self.assertEqual(canonicalize_str(1e-7), "1e-7")

    def test_integral_floats_lose_the_fraction(self):
        self.assertEqual(canonicalize_str(3.0), "3")
        self.assertEqual(canonicalize_str(100.0), "100")

    def test_negative_zero_folds(self):
        self.assertEqual(canonicalize_str(-0.0), "0")
        self.assertEqual(canonicalize_str(0.0), "0")

    def test_shortest_round_trip_digits(self):
        self.assertEqual(canonicalize_str(1.5), "1.5")
        self.assertEqual(canonicalize_str(0.1), "0.1")
        # 2**-1074, the smallest positive double, must still round-trip.
        self.assertEqual(float(canonicalize_str(5e-324)), 5e-324)

    def test_mantissa_gets_a_point_only_when_it_has_digits_to_spare(self):
        self.assertEqual(canonicalize_str(1.2345e-9), "1.2345e-9")
        self.assertEqual(canonicalize_str(1e-9), "1e-9")

    def test_non_finite_has_no_canonical_form(self):
        for bad in (float("nan"), float("inf"), float("-inf")):
            with self.assertRaises(JCSError):
                canonicalize_str(bad)

    def test_safe_integer_profile_is_enforced_on_ints(self):
        self.assertEqual(canonicalize_str(2 ** 53 - 1), "9007199254740991")
        with self.assertRaises(JCSError):
            canonicalize_str(2 ** 53)
        with self.assertRaises(JCSError):
            canonicalize_str(-(2 ** 53))


class TestStrings(unittest.TestCase):
    def test_two_character_escapes(self):
        self.assertEqual(canonicalize_str("\b\t\n\f\r"), r'"\b\t\n\f\r"')
        self.assertEqual(canonicalize_str('a"b\\c'), r'"a\"b\\c"')

    def test_other_control_characters_use_lowercase_four_digit_escapes(self):
        self.assertEqual(canonicalize_str("\x00\x1f"), '"\\u0000\\u001f"')

    def test_non_ascii_is_literal_utf8(self):
        self.assertEqual(canonicalize("é"), b'"\xc3\xa9"')

    def test_del_and_c1_are_not_escaped(self):
        # Only C0 is escaped; RFC 8785 leaves U+007F and C1 literal.
        self.assertEqual(canonicalize(""), b'"\x7f"')
        self.assertNotIn(b"\\u", canonicalize(""))


class TestMemberOrdering(unittest.TestCase):
    def test_sorted_by_utf16_code_unit_not_code_point(self):
        # U+FF3A (BMP) and U+1D400 (astral). By code point U+FF3A sorts first.
        # By UTF-16 code unit the astral character leads, because its high
        # surrogate D835 is below FF3A. RFC 8785 demands the second order.
        bmp, astral = "Ｚ", "\U0001d400"
        self.assertLess(bmp, astral)  # Python's own comparison
        self.assertEqual(sort_utf16([bmp, astral]), [astral, bmp])
        out = canonicalize_str({bmp: 1, astral: 2})
        self.assertLess(out.index(astral), out.index(bmp))

    def test_utf16_key_is_big_endian_code_units(self):
        self.assertEqual(utf16_key("A"), b"\x00A")

    def test_ordering_is_independent_of_insertion_order(self):
        a = canonicalize_str({"b": 1, "a": 2, "c": 3})
        b = canonicalize_str({"c": 3, "b": 1, "a": 2})
        self.assertEqual(a, b)
        self.assertEqual(a, '{"a":2,"b":1,"c":3}')

    def test_empty_string_member_sorts_first(self):
        self.assertEqual(canonicalize_str({"a": 1, "": 2}), '{"":2,"a":1}')

    def test_nested_objects_sort_at_every_depth(self):
        self.assertEqual(
            canonicalize_str({"z": {"b": 1, "a": 2}}), '{"z":{"a":2,"b":1}}'
        )


class TestStructure(unittest.TestCase):
    def test_no_insignificant_whitespace(self):
        self.assertEqual(
            canonicalize_str({"a": [1, 2, {"b": None}]}), '{"a":[1,2,{"b":null}]}'
        )

    def test_literals(self):
        self.assertEqual(canonicalize_str([True, False, None]), "[true,false,null]")

    def test_bool_is_not_serialised_as_an_integer(self):
        # bool subclasses int in Python; the check order matters.
        self.assertEqual(canonicalize_str(True), "true")
        self.assertEqual(canonicalize_str({"x": False}), '{"x":false}')

    def test_empty_containers(self):
        self.assertEqual(canonicalize_str({}), "{}")
        self.assertEqual(canonicalize_str([]), "[]")

    def test_output_is_utf8_bytes(self):
        self.assertIsInstance(canonicalize({"a": 1}), bytes)

    def test_non_string_member_name_is_refused(self):
        with self.assertRaises(JCSError):
            canonicalize_str({1: "a"})

    def test_unknown_type_is_refused(self):
        with self.assertRaises(JCSError):
            canonicalize_str(object())


if __name__ == "__main__":
    unittest.main()
