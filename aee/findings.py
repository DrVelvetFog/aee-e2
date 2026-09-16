"""This rail's refusal vocabulary.

The corpus manifest's ``comparisonSurface`` marks ``verdict`` and, on an
accepted statement, ``result`` as normative, and refusal ``codes`` as measured:

> The codes on a reject entry are the reference verifier's own vocabulary, not
> the specification's: a rail names a reason from whatever set it declares, and
> a differing code is a reason-parity datum rather than a failure. Report that
> parity as its own figure. The divergences worth finding are the statements two
> rails both reject for different reasons, and scoring on codes would hide
> exactly those.

So this vocabulary is declared, not matched. It is named after the rule each
code refuses rather than after any other implementation's spelling.

The head spec constrains what a refusal may *say*, and those constraints are
normative even though the code itself is not:

> Where a refusal names a comparison, the set it names MUST be the set the
> implementation evaluated.

Specifically a verifier MUST NOT name a comparison whose operand set was empty,
MUST NOT name a set wider than the one the check ranged over, MUST NOT describe
a commitment comparison as ranging over a set whose membership it cannot
exhibit, and MUST NOT name a conjunct it did not reach. Messages here are
written to that standard: a digest mismatch says the recompute differs and does
not claim to know which element differed.
"""

__all__ = ["Finding", "Verdict", "VALID", "INVALID", "INDETERMINATE"]

VALID = "valid"
INVALID = "invalid"
INDETERMINATE = "indeterminate"


class Finding:
    """One refused rule, with the code this rail declares for it."""

    __slots__ = ("code", "message", "where")

    def __init__(self, code, message, where=None):
        self.code = code
        self.message = message
        self.where = where

    def __repr__(self):
        return "Finding(%r, %r)" % (self.code, self.message)

    def __eq__(self, other):
        if isinstance(other, Finding):
            return self.code == other.code and self.message == other.message
        return NotImplemented

    def __str__(self):
        if self.where:
            return "%s: %s (%s)" % (self.code, self.message, self.where)
        return "%s: %s" % (self.code, self.message)


class Verdict:
    """The outcome for one statement: a token plus every finding behind it."""

    __slots__ = ("verdict", "result", "findings")

    def __init__(self, verdict, result=None, findings=()):
        self.verdict = verdict
        self.result = result
        self.findings = tuple(findings)

    @property
    def codes(self):
        """Declared codes, in the order the checks produced them."""
        return tuple(finding.code for finding in self.findings)

    def __repr__(self):
        return "Verdict(%r, result=%r, codes=%r)" % (
            self.verdict,
            self.result,
            self.codes,
        )
