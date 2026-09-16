"""The whole byte-pure verifier: bytes in, verdict out.

Spec basis (head 25ac8581), Parsing Rules:

> A verifier proceeds in two stages. Stage one is byte-pure: four validity
> steps, each a function of the carried statement alone, and all four are
> consumption preconditions: (1) statement well-formedness, including the
> vocabulary rules and, for substrate-carrying statements, run-binding
> derivability; (2) the coverage validity requirements; (3) the ``result``
> recompute; (4) manifest and vocabulary digest integrity. Stage two is
> trust-relative ...

This module runs stage one and stops. Stage two needs keys and a consumer
policy, and the corpus is offline, so nothing here verifies a signature.

Steps one, three and four live in :mod:`aee.wellformed`; step two in
:mod:`aee.coverage`. The reading of the profile itself -- strict I-JSON over the
raw bytes -- runs first, because every later step reads decoded values and the
spec puts the byte check before any of them.

A statement is ``valid`` when no step produces a finding, and ``invalid``
otherwise. There is no third outcome: the ``verdict`` vocabulary this rail emits
is two-valued. Where the corpus marks a vector's *reason* as reading-dependent
it still carries ``expected.verdict: "invalid"``, so a two-valued verdict is
what the comparison surface asks for; the reading-dependence lands on the code,
which is measured rather than scored.
"""

from .coverage import check_coverage_validity
from .findings import INVALID, VALID, Finding, Verdict
from .ijson import IJSONError, loads
from .wellformed import check_wellformed

__all__ = ["verify_bytes", "verify_statement"]


def verify_statement(statement):
    """Verdict for an already-parsed statement."""
    findings = list(check_wellformed(statement))
    findings.extend(check_coverage_validity(statement))
    if findings:
        return Verdict(INVALID, None, findings)
    return Verdict(VALID, statement["predicate"]["result"], ())


def verify_bytes(raw):
    """Verdict for the raw bytes of one statement.

    The profile check runs first and fails closed: a statement that is not
    strict I-JSON is invalid without any later step being consulted, because
    every later step would be reading values the profile says may not be read.
    """
    try:
        statement = loads(raw)
    except IJSONError as exc:
        return Verdict(
            INVALID, None, [Finding("ijson-profile", "statement bytes: %s" % exc)]
        )
    return verify_statement(statement)
