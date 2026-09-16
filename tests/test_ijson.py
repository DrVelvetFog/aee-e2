"""The strict I-JSON profile: duplicates, string bytes, depth, safe integers."""

import unittest

from aee.ijson import IJSONError, is_bmp_only, is_noncharacter, loads


class TestAcceptance(unittest.TestCase):
    def test_round_trips_ordinary_documents(self):
        self.assertEqual(
            loads(b'{"a":1,"b":[true,false,null],"c":{"d":"e"}}'),
            {"a": 1, "b": [True, False, None], "c": {"d": "e"}},
        )

    def test_accepts_bytes_and_str(self):
        self.assertEqual(loads(b'{"a":1}'), loads('{"a":1}'))

    def test_whitespace_between_tokens(self):
        self.assertEqual(loads(b' { "a" : [ 1 , 2 ] } '), {"a": [1, 2]})

    def test_empty_containers(self):
        self.assertEqual(loads(b"{}"), {})
        self.assertEqual(loads(b"[]"), [])

    def test_simple_escapes(self):
        self.assertEqual(loads(r'"\"\\\/\b\f\n\r\t"'), '"\\/\b\f\n\r\t')

    def test_surrogate_pair_escape_makes_one_astral_character(self):
        self.assertEqual(loads(r'"😀"'), "\U0001f600")

    def test_replacement_character_is_a_legal_scalar(self):
        # U+FFFD is only suspect when a decoder manufactured it. Written
        # deliberately it is an ordinary character.
        self.assertEqual(loads('"�"'), "�")


class TestDuplicateMembers(unittest.TestCase):
    def test_top_level_duplicate(self):
        with self.assertRaises(IJSONError) as caught:
            loads(b'{"a":1,"a":2}')
        self.assertIn("duplicate member", str(caught.exception))

    def test_nested_duplicate(self):
        with self.assertRaises(IJSONError):
            loads(b'{"outer":{"a":1,"a":2}}')

    def test_duplicate_inside_an_array_element(self):
        with self.assertRaises(IJSONError):
            loads(b'[{"a":1,"a":2}]')

    def test_the_last_value_is_not_silently_kept(self):
        # json.loads returns {"a": 2} here. The profile refuses instead.
        with self.assertRaises(IJSONError):
            loads(b'{"a":1,"a":2}')

    def test_same_name_in_sibling_objects_is_fine(self):
        self.assertEqual(loads(b'[{"a":1},{"a":2}]'), [{"a": 1}, {"a": 2}])


class TestNestingDepth(unittest.TestCase):
    def test_outermost_container_is_depth_one(self):
        self.assertEqual(loads(b"[]", max_depth=1), [])
        with self.assertRaises(IJSONError):
            loads(b"[[]]", max_depth=1)

    def test_scalars_do_not_increase_depth(self):
        self.assertEqual(loads(b'{"a":1}', max_depth=1), {"a": 1})

    def test_one_hundred_and_twenty_eight_is_allowed(self):
        value = loads(b"[" * 128 + b"]" * 128)
        for _ in range(127):
            value = value[0]
        self.assertEqual(value, [])

    def test_one_hundred_and_twenty_nine_is_refused(self):
        with self.assertRaises(IJSONError) as caught:
            loads(b"[" * 129 + b"]" * 129)
        self.assertIn("nesting depth", str(caught.exception))

    def test_objects_and_arrays_count_the_same(self):
        deep = b'{"a":' * 129 + b"1" + b"}" * 129
        with self.assertRaises(IJSONError):
            loads(deep)


class TestStringBytes(unittest.TestCase):
    def test_raw_control_character_is_refused(self):
        with self.assertRaises(IJSONError) as caught:
            loads(b'"a\x01b"')
        self.assertIn("below U+0020", str(caught.exception))

    def test_raw_newline_inside_a_string_is_refused(self):
        with self.assertRaises(IJSONError):
            loads(b'"a\nb"')

    def test_u007f_is_not_a_control_character_here(self):
        # The rule names U+0020 as the floor; DEL is above it.
        self.assertEqual(loads(b'"\x7f"'), "\x7f")

    def test_escape_needs_exactly_four_hex_digits(self):
        for bad in (r'"\u041"', r'"A1"[', r'"\uZZZZ"'):
            with self.assertRaises(IJSONError):
                loads(bad)

    def test_permissive_integer_forms_are_refused(self):
        # The spec names this case: a reader built on a permissive integer
        # parser would accept \u+041.
        with self.assertRaises(IJSONError):
            loads(r'"\u+041"')
        with self.assertRaises(IJSONError):
            loads(r'"\u 041"')
        with self.assertRaises(IJSONError):
            loads(r'"\u0x41"')

    def test_unknown_escape_is_refused(self):
        with self.assertRaises(IJSONError):
            loads(r'"\x41"')

    def test_lone_high_surrogate_escape(self):
        with self.assertRaises(IJSONError):
            loads(r'"\ud800"')

    def test_lone_low_surrogate_escape(self):
        with self.assertRaises(IJSONError) as caught:
            loads(r'"\udc00"')
        self.assertIn("unpaired low surrogate", str(caught.exception))

    def test_high_surrogate_followed_by_a_plain_character(self):
        with self.assertRaises(IJSONError):
            loads(r'"\ud800a"')

    def test_high_surrogate_followed_by_a_non_surrogate_escape(self):
        with self.assertRaises(IJSONError):
            loads(r'"\ud800A"')


class TestUTF8Encoding(unittest.TestCase):
    def test_overlong_form_is_refused(self):
        # C0 80 is an overlong encoding of U+0000.
        with self.assertRaises(IJSONError) as caught:
            loads(b'"\xc0\x80"')
        self.assertIn("UTF-8", str(caught.exception))

    def test_surrogate_encoded_directly_in_utf8_is_refused(self):
        # ED A0 80 is CESU-8 for U+D800.
        with self.assertRaises(IJSONError):
            loads(b'"\xed\xa0\x80"')

    def test_truncated_sequence_is_refused(self):
        with self.assertRaises(IJSONError):
            loads(b'"\xe2\x82"')

    def test_no_replacement_character_is_manufactured(self):
        # The failure mode the rule exists to prevent: a lenient decoder would
        # return U+FFFD here instead of refusing.
        with self.assertRaises(IJSONError):
            loads(b'"\xff"')


class TestNoncharacters(unittest.TestCase):
    def test_predicate_covers_the_arabic_block(self):
        self.assertTrue(is_noncharacter(0xFDD0))
        self.assertTrue(is_noncharacter(0xFDEF))
        self.assertFalse(is_noncharacter(0xFDCF))
        self.assertFalse(is_noncharacter(0xFDF0))

    def test_predicate_covers_the_last_two_of_every_plane(self):
        for plane in (0x0, 0x1, 0x10):
            base = plane << 16
            self.assertTrue(is_noncharacter(base | 0xFFFE))
            self.assertTrue(is_noncharacter(base | 0xFFFF))
            self.assertFalse(is_noncharacter(base | 0xFFFD))

    def test_escaped_noncharacter_in_a_value(self):
        with self.assertRaises(IJSONError) as caught:
            loads(r'{"a":"￾"}')
        self.assertIn("noncharacter", str(caught.exception))

    def test_escaped_noncharacter_in_a_member_name(self):
        with self.assertRaises(IJSONError):
            loads(r'{"﷐":1}')

    def test_literal_noncharacter(self):
        with self.assertRaises(IJSONError):
            loads('"￾"')

    def test_astral_noncharacter_built_from_a_surrogate_pair(self):
        # U+1FFFE, written the only way JSON escapes can reach it.
        with self.assertRaises(IJSONError):
            loads(r'"🿾"')

    def test_neighbouring_code_points_are_accepted(self):
        self.assertEqual(loads(r'"�"'), "�")
        self.assertEqual(loads(r'"ﷰ"'), "ﷰ")


class TestNumbers(unittest.TestCase):
    def test_safe_integer_boundary(self):
        self.assertEqual(loads(b"9007199254740991"), 2 ** 53 - 1)
        with self.assertRaises(IJSONError) as caught:
            loads(b"9007199254740992")
        self.assertIn("2**53", str(caught.exception))

    def test_negative_safe_integer_boundary(self):
        self.assertEqual(loads(b"-9007199254740991"), -(2 ** 53 - 1))
        with self.assertRaises(IJSONError):
            loads(b"-9007199254740992")

    def test_exponent_form_is_not_treated_as_an_integer(self):
        # Recorded reading, not an oversight: the canonical form this same
        # section pins gives 1e+21 an explicit layout.
        self.assertEqual(loads(b"1e21"), 1e21)

    def test_json_number_grammar(self):
        for bad in (b"+1", b".5", b"5.", b"01", b"-01", b"1e", b"1e+", b"--1"):
            with self.assertRaises(IJSONError):
                loads(bad)

    def test_zero_forms(self):
        self.assertEqual(loads(b"0"), 0)
        self.assertEqual(loads(b"-0"), 0)
        self.assertEqual(loads(b"0.5"), 0.5)

    def test_non_finite_words_are_not_json(self):
        for bad in (b"NaN", b"Infinity", b"-Infinity"):
            with self.assertRaises(IJSONError):
                loads(bad)

    def test_overflow_to_infinity_is_refused(self):
        with self.assertRaises(IJSONError) as caught:
            loads(b"1e400")
        self.assertIn("finite", str(caught.exception))


class TestGrammar(unittest.TestCase):
    def test_trailing_content_is_refused(self):
        with self.assertRaises(IJSONError):
            loads(b'{"a":1} {"b":2}')

    def test_trailing_comma_is_refused(self):
        with self.assertRaises(IJSONError):
            loads(b'{"a":1,}')
        with self.assertRaises(IJSONError):
            loads(b"[1,]")

    def test_unquoted_member_name_is_refused(self):
        with self.assertRaises(IJSONError):
            loads(b"{a:1}")

    def test_single_quotes_are_refused(self):
        with self.assertRaises(IJSONError):
            loads(b"'a'")

    def test_only_the_three_literals(self):
        for bad in (b"True", b"NULL", b"undefined"):
            with self.assertRaises(IJSONError):
                loads(bad)

    def test_empty_input_is_refused(self):
        with self.assertRaises(IJSONError):
            loads(b"")

    def test_unterminated_containers(self):
        for bad in (b'{"a":1', b"[1", b'"abc'):
            with self.assertRaises(IJSONError):
                loads(bad)

    def test_wrong_type_is_refused(self):
        with self.assertRaises(IJSONError):
            loads(7)


class TestBMPHelper(unittest.TestCase):
    def test_bmp_only(self):
        self.assertTrue(is_bmp_only("plain"))
        self.assertTrue(is_bmp_only("￿"))
        self.assertFalse(is_bmp_only("\U0001d400"))

    def test_empty_string_is_bmp_only(self):
        self.assertTrue(is_bmp_only(""))


if __name__ == "__main__":
    unittest.main()
