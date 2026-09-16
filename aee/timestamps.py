"""The timestamp profile ``issuedAt`` pins, shared with ``armedAt``.

Spec basis (head 25ac8581), ``issuedAt``:

> ``Timestamp`` is the framework's field type, which requires RFC 3339 in the
> UTC timezone, and this document pins the two choices that type leaves open. A
> statement is canonicalized and digested as its bytes, so no verifier may
> normalize the field before reading it and the admissible set has to be written
> down; left open, one implementation is quietly stricter than another and the
> divergence surfaces only when a statement crosses between them. The date-time
> separator and the zone designator MUST be uppercase, never the lowercase ``t``
> and ``z`` that RFC 3339 also admits, and the zone designator MUST be ``Z``,
> ``+00:00`` or ``-00:00``, never a non-zero offset such as ``+05:00``.

``-00:00`` is admitted deliberately: RFC 3339 section 4.3 gives it the meaning
that the instant in UTC is known while the offset to local time is not, "which
describes where the producer stood and not when it signed, and the instant is
the only thing this document reads from the field".

"``armedAt`` carries the same profile, defined here and cited from the arming
record so that the two fields cannot drift apart" -- hence one module, used by
both.

No normalisation happens here. The field is read, not rewritten, because the
statement is digested as its bytes.
"""

import datetime
import re

__all__ = ["ZONE_FORMS", "is_admissible", "parse_instant"]

#: The three zone designators the profile admits.
ZONE_FORMS = ("Z", "+00:00", "-00:00")

# Uppercase T only; uppercase Z only; second is required; a fraction is
# optional and RFC 3339 puts no bound on its length.
_PATTERN = re.compile(
    r"^(?P<date>\d{4}-\d{2}-\d{2})"
    r"T"
    r"(?P<time>\d{2}:\d{2}:\d{2})"
    r"(?P<fraction>\.\d+)?"
    r"(?P<zone>Z|\+00:00|-00:00)$"
)


def _fields(value):
    if not isinstance(value, str):
        return None
    match = _PATTERN.match(value)
    if match is None:
        return None
    # The grammar admits impossible dates such as 2026-02-30; RFC 3339 requires
    # a real date, so the calendar has the last word.
    try:
        moment = datetime.datetime.strptime(
            match.group("date") + " " + match.group("time"), "%Y-%m-%d %H:%M:%S"
        )
    except ValueError:
        return None
    return match, moment


def is_admissible(value):
    """True when ``value`` is inside the profile."""
    return _fields(value) is not None


def parse_instant(value):
    """The instant as a timezone-aware UTC datetime, or ``None`` if inadmissible.

    "the instant is the only thing this document reads from the field", so the
    three zone forms all yield the same instant and the distinction between them
    is not carried forward.
    """
    fields = _fields(value)
    if fields is None:
        return None
    match, moment = fields
    fraction = match.group("fraction")
    if fraction:
        digits = (fraction[1:] + "000000")[:6]
        moment = moment.replace(microsecond=int(digits))
    return moment.replace(tzinfo=datetime.timezone.utc)
