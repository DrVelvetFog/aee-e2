"""Strict I-JSON reader for the profile Prerequisites states.

Spec basis (head 25ac8581), Prerequisites:

* "The whole statement JSON is parsed as strict I-JSON: a duplicate member
  anywhere in the statement, at any depth and not only inside a covering record
  payload, makes the statement malformed. ... a verifier MUST reject a duplicate
  member statement-wide, fail-closed."
* "A verifier MUST reject, statement-wide and fail-closed, any statement in
  which a string literal is not a well-formed sequence of Unicode scalar
  values." That is: valid UTF-8 with no overlong form and no surrogate encoded
  directly in UTF-8; a ``\\u`` escape naming a high surrogate immediately
  followed by one naming a low surrogate, with an unpaired half of either
  malformed; no raw unescaped character below U+0020; and a ``\\u`` escape of
  exactly four hexadecimal digits, "with no sign, no whitespace and no radix
  prefix, so that a reader built on a permissive integer parser does not accept
  ``\\u+041`` where a strict one rejects it".
* The profile "also excludes the Unicode noncharacters -- the code points
  U+FDD0 through U+FDEF, and U+nFFFE and U+nFFFF in every plane", "rejected
  wherever a string literal appears, at any depth and in both member-name and
  value position".
* "A verifier MUST reject, fail-closed, a statement whose JSON nesting depth
  exceeds 128. Nesting depth is the number of arrays and objects that are open
  at a given point, counting the outermost ``{`` of the statement as depth 1;
  scalar values do not increase it. ... Record payloads are parsed under the
  same bound."
* "integers with magnitude at or above 2**53 MUST be rejected".

Why this is a scanner rather than a wrapper around ``json.loads``: the standard
library keeps the last of a repeated member rather than refusing it, and accepts
an unpaired surrogate escape. The spec also requires the string check to run
"on the raw bytes, before any decoded string is read", because "a lenient
decoder does not fail on ill-formed bytes, it substitutes U+FFFD for them, and
every check downstream of the decode then reads a string the producer never
wrote". This module decodes with Python's strict UTF-8 decoder, which raises
rather than substituting -- no U+FFFD can be manufactured from ill-formed input,
so no downstream check can read one -- and rejects surrogates and overlong forms
in the encoding itself. Every other rule is enforced by the scan below.

Underdetermined, recorded rather than guessed at: the safe-integer rule names
"integers", and this reader applies it to numbers written in integer form. A
number written with an exponent, such as ``1e21``, is not refused here even
though its value is integral and above the bound, because the canonical form
the same Prerequisites section pins gives ``1e+21`` an explicit layout, which a
blanket refusal would make unreachable. See NOTES.md.
"""

__all__ = [
    "IJSONError",
    "MAX_DEPTH",
    "SAFE_INT_LIMIT",
    "is_bmp_only",
    "is_noncharacter",
    "loads",
]

MAX_DEPTH = 128
SAFE_INT_LIMIT = 2 ** 53

_HEX = "0123456789abcdefABCDEF"
_WS = " \t\n\r"
_SIMPLE_ESCAPES = {
    '"': '"',
    "\\": "\\",
    "/": "/",
    "b": "\b",
    "f": "\f",
    "n": "\n",
    "r": "\r",
    "t": "\t",
}


class IJSONError(ValueError):
    """Input outside the strict I-JSON profile. Always fail-closed."""


def is_noncharacter(cp):
    """U+FDD0..U+FDEF, and U+nFFFE / U+nFFFF in every plane."""
    return 0xFDD0 <= cp <= 0xFDEF or (cp & 0xFFFE) == 0xFFFE


def is_bmp_only(text):
    """True when no code point is above U+FFFF.

    Prerequisites restricts signed canonical surfaces to the BMP so that
    "UTF-16 code-unit order and code-point order coincide". The reader does not
    apply this itself: it is a property of particular surfaces, not of the
    profile, and the caller knows which surface it is holding.
    """
    return all(ord(ch) <= 0xFFFF for ch in text)


class _Scanner:
    def __init__(self, text, max_depth):
        self.s = text
        self.i = 0
        self.n = len(text)
        self.max_depth = max_depth

    def fail(self, message):
        raise IJSONError("%s at position %d" % (message, self.i))

    def skip_ws(self):
        s, n = self.s, self.n
        i = self.i
        while i < n and s[i] in _WS:
            i += 1
        self.i = i

    def expect(self, ch):
        if self.i >= self.n or self.s[self.i] != ch:
            self.fail("expected %r" % ch)
        self.i += 1

    def parse(self):
        self.skip_ws()
        value = self.value(0)
        self.skip_ws()
        if self.i != self.n:
            self.fail("trailing content after the top-level value")
        return value

    def value(self, depth):
        if self.i >= self.n:
            self.fail("unexpected end of input")
        ch = self.s[self.i]
        if ch == "{":
            return self.object(depth + 1)
        if ch == "[":
            return self.array(depth + 1)
        if ch == '"':
            return self.string()
        if ch == "t":
            return self.literal("true", True)
        if ch == "f":
            return self.literal("false", False)
        if ch == "n":
            return self.literal("null", None)
        if ch == "-" or ch.isdigit():
            return self.number()
        self.fail("unexpected character %r" % ch)

    def literal(self, word, value):
        if self.s[self.i : self.i + len(word)] != word:
            self.fail("unexpected character %r" % self.s[self.i])
        self.i += len(word)
        return value

    def enter(self, depth):
        if depth > self.max_depth:
            self.fail("nesting depth %d exceeds the bound of %d" % (depth, self.max_depth))

    def object(self, depth):
        self.enter(depth)
        self.expect("{")
        out = {}
        self.skip_ws()
        if self.i < self.n and self.s[self.i] == "}":
            self.i += 1
            return out
        while True:
            self.skip_ws()
            if self.i >= self.n or self.s[self.i] != '"':
                self.fail("expected a member name")
            name = self.string()
            if name in out:
                raise IJSONError(
                    "duplicate member %r; a repeated member makes the input "
                    "malformed at any depth" % name
                )
            self.skip_ws()
            self.expect(":")
            self.skip_ws()
            out[name] = self.value(depth)
            self.skip_ws()
            if self.i >= self.n:
                self.fail("unterminated object")
            if self.s[self.i] == ",":
                self.i += 1
                continue
            if self.s[self.i] == "}":
                self.i += 1
                return out
            self.fail("expected %r or %r" % (",", "}"))

    def array(self, depth):
        self.enter(depth)
        self.expect("[")
        out = []
        self.skip_ws()
        if self.i < self.n and self.s[self.i] == "]":
            self.i += 1
            return out
        while True:
            self.skip_ws()
            out.append(self.value(depth))
            self.skip_ws()
            if self.i >= self.n:
                self.fail("unterminated array")
            if self.s[self.i] == ",":
                self.i += 1
                continue
            if self.s[self.i] == "]":
                self.i += 1
                return out
            self.fail("expected %r or %r" % (",", "]"))

    def hex4(self):
        """Exactly four hexadecimal digits: no sign, no whitespace, no prefix."""
        digits = self.s[self.i : self.i + 4]
        if len(digits) != 4 or any(d not in _HEX for d in digits):
            self.fail("a \\u escape takes exactly four hexadecimal digits")
        self.i += 4
        return int(digits, 16)

    def escape(self):
        self.i += 1  # the backslash
        if self.i >= self.n:
            self.fail("unterminated escape")
        ch = self.s[self.i]
        simple = _SIMPLE_ESCAPES.get(ch)
        if simple is not None:
            self.i += 1
            return simple
        if ch != "u":
            self.fail("unknown escape \\%s" % ch)
        self.i += 1
        cp = self.hex4()
        if 0xD800 <= cp <= 0xDBFF:
            if self.s[self.i : self.i + 2] != "\\u":
                self.fail("a high surrogate escape must be followed by a low one")
            self.i += 2
            low = self.hex4()
            if not 0xDC00 <= low <= 0xDFFF:
                self.fail("a high surrogate escape must be followed by a low one")
            cp = 0x10000 + ((cp - 0xD800) << 10) + (low - 0xDC00)
        elif 0xDC00 <= cp <= 0xDFFF:
            self.fail("an unpaired low surrogate escape is malformed")
        if is_noncharacter(cp):
            self.fail("U+%04X is a Unicode noncharacter" % cp)
        return chr(cp)

    def string(self):
        self.expect('"')
        parts = []
        s, n = self.s, self.n
        start = self.i
        while True:
            if self.i >= n:
                self.fail("unterminated string")
            ch = s[self.i]
            if ch == '"':
                parts.append(s[start : self.i])
                self.i += 1
                return "".join(parts)
            if ch == "\\":
                parts.append(s[start : self.i])
                parts.append(self.escape())
                start = self.i
                continue
            cp = ord(ch)
            if cp < 0x20:
                self.fail("raw character U+%04X below U+0020 in a string" % cp)
            if is_noncharacter(cp):
                self.fail("U+%04X is a Unicode noncharacter" % cp)
            self.i += 1

    def number(self):
        s, n = self.s, self.n
        start = self.i
        if self.i < n and s[self.i] == "-":
            self.i += 1
        if self.i >= n or not s[self.i].isdigit():
            self.fail("a number needs at least one digit")
        if s[self.i] == "0":
            self.i += 1
        else:
            while self.i < n and s[self.i].isdigit():
                self.i += 1
        if self.i < n and s[self.i].isdigit():
            self.fail("a number must not carry a leading zero")

        is_integer = True
        if self.i < n and s[self.i] == ".":
            is_integer = False
            self.i += 1
            if self.i >= n or not s[self.i].isdigit():
                self.fail("a fraction needs at least one digit")
            while self.i < n and s[self.i].isdigit():
                self.i += 1
        if self.i < n and s[self.i] in "eE":
            is_integer = False
            self.i += 1
            if self.i < n and s[self.i] in "+-":
                self.i += 1
            if self.i >= n or not s[self.i].isdigit():
                self.fail("an exponent needs at least one digit")
            while self.i < n and s[self.i].isdigit():
                self.i += 1

        raw = s[start : self.i]
        if is_integer:
            value = int(raw)
            if abs(value) >= SAFE_INT_LIMIT:
                raise IJSONError(
                    "integer %s has magnitude at or above 2**53 and is outside "
                    "the safe range" % raw
                )
            return value
        value = float(raw)
        if value != value or value in (float("inf"), float("-inf")):
            raise IJSONError("number %s is not a finite double" % raw)
        return value


def loads(data, *, max_depth=MAX_DEPTH):
    """Parse ``data`` under the strict I-JSON profile.

    Accepts bytes, which is the form the rules are written against. A ``str`` is
    accepted for callers that already hold decoded text, but a caller holding
    bytes should pass them: the encoding checks only run on bytes.
    """
    if isinstance(data, (bytes, bytearray, memoryview)):
        try:
            text = bytes(data).decode("utf-8")
        except UnicodeDecodeError as exc:
            # Python's strict decoder refuses overlong forms and surrogates
            # encoded directly in UTF-8, and raises rather than substituting
            # U+FFFD, which is what the spec requires of this stage.
            raise IJSONError("input is not well-formed UTF-8: %s" % exc) from exc
    elif isinstance(data, str):
        text = data
    else:
        raise IJSONError("expected bytes or str, got %s" % type(data).__name__)
    return _Scanner(text, max_depth).parse()
