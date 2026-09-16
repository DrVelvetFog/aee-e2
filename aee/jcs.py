"""RFC 8785 (JCS) canonicalisation.

Spec basis (head 25ac8581): Prerequisites names RFC 8785 as the canonical form
the digest bindings are defined over, and imposes the RFC 7493 safe-integer
profile on canonicalised content -- integers of magnitude at or above 2**53 are
rejected, so every rail derives identical bytes.

Number formatting follows ECMAScript ``Number::toString``, which RFC 8785
section 3.2.2.3 defers to. The shortest round-tripping digit string comes from
``repr``; this module only re-lays-out those digits per the ECMAScript rules,
which differ from Python's at both ends of the range (ECMAScript switches to
exponential at 1e21, Python at 1e16).
Where the safe-integer rule is enforced: this module rejects a Python ``int``
of magnitude 2**53 or above, because such a value has no faithful double form
and the profile forbids it outright. A ``float`` is already a double and is
formatted by the ECMAScript rules whatever its magnitude; rejecting an
out-of-range *input* number is the reader's job, not the serialiser's, and is
done there against the raw bytes.
"""

from decimal import Decimal

__all__ = ["canonicalize", "canonicalize_str", "utf16_key", "sort_utf16", "JCSError"]

SAFE_INT_LIMIT = 2 ** 53

# RFC 8785 section 3.2.2.2: two-character escapes, then \u00xx for the rest of C0.
_SHORT_ESCAPES = {
    0x08: "\\b",
    0x09: "\\t",
    0x0A: "\\n",
    0x0C: "\\f",
    0x0D: "\\r",
    0x22: '\\"',
    0x5C: "\\\\",
}


class JCSError(ValueError):
    """A value that has no canonical form under the profile this spec pins."""


def utf16_key(s):
    """Sort key placing strings in UTF-16 code-unit order.

    RFC 8785 sorts object members by UTF-16 code unit. Python compares strings
    by code point, which orders a supplementary-plane name differently from one
    in U+E000..U+FFFF. Big-endian UTF-16 bytes compare in code-unit order, so
    they are the key. Prerequisites restricts signed canonical surfaces to the
    BMP, where the two orders coincide; this module does not rely on that.
    """
    return s.encode("utf-16-be", "surrogatepass")


def sort_utf16(strings):
    """Return ``strings`` sorted ascending by UTF-16 code unit."""
    return sorted(strings, key=utf16_key)


def _escape(s):
    out = ['"']
    for ch in s:
        cp = ord(ch)
        esc = _SHORT_ESCAPES.get(cp)
        if esc is not None:
            out.append(esc)
        elif cp < 0x20:
            out.append("\\u%04x" % cp)
        else:
            out.append(ch)
    out.append('"')
    return "".join(out)


def _number(x):
    """ECMAScript Number::toString for a finite double."""
    if x != x or x in (float("inf"), float("-inf")):
        raise JCSError("NaN and Infinity have no JSON form")
    if x == 0:
        return "0"  # also folds -0.0, per Number::toString
    if x < 0:
        return "-" + _number(-x)

    # repr gives the shortest digit string that round-trips; Decimal splits it
    # into digits and an exponent without introducing binary error of its own.
    digits, exp = Decimal(repr(x)).as_tuple()[1:]
    digits = list(digits)
    while len(digits) > 1 and digits[-1] == 0:
        digits.pop()
        exp += 1
    s = "".join(map(str, digits))
    k = len(s)
    n = exp + k

    if k <= n <= 21:
        return s + "0" * (n - k)
    if 0 < n <= 21:
        return s[:n] + "." + s[n:]
    if -6 < n <= 0:
        return "0." + "0" * (-n) + s
    e = n - 1
    mant = s if k == 1 else s[0] + "." + s[1:]
    return "%se%s%d" % (mant, "+" if e >= 0 else "-", abs(e))


def _serialize(value, out, depth):
    if value is None:
        out.append("null")
    elif value is True:
        out.append("true")
    elif value is False:
        out.append("false")
    elif isinstance(value, int):
        # bool is a subclass of int and is handled above.
        if abs(value) >= SAFE_INT_LIMIT:
            raise JCSError(
                "integer magnitude %d is outside the RFC 7493 safe range" % value
            )
        out.append(str(value))
    elif isinstance(value, float):
        if value.is_integer() and abs(value) < SAFE_INT_LIMIT:
            out.append(str(int(value)))
        else:
            out.append(_number(value))
    elif isinstance(value, str):
        out.append(_escape(value))
    elif isinstance(value, (list, tuple)):
        out.append("[")
        for i, item in enumerate(value):
            if i:
                out.append(",")
            _serialize(item, out, depth + 1)
        out.append("]")
    elif isinstance(value, dict):
        out.append("{")
        keys = list(value)
        for key in keys:
            if not isinstance(key, str):
                raise JCSError("object member name must be a string, got %r" % (key,))
        first = True
        for key in sort_utf16(keys):
            if not first:
                out.append(",")
            first = False
            out.append(_escape(key))
            out.append(":")
            _serialize(value[key], out, depth + 1)
        out.append("}")
    else:
        raise JCSError("no canonical form for %r" % (type(value).__name__,))


def canonicalize_str(value):
    """Canonical JSON text for ``value``."""
    out = []
    _serialize(value, out, 1)
    return "".join(out)


def canonicalize(value):
    """Canonical JSON bytes for ``value`` (UTF-8, as RFC 8785 requires)."""
    return canonicalize_str(value).encode("utf-8")
