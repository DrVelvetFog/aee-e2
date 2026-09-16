"""The ``result`` recompute.

Spec basis (head 25ac8581), ``result``:

> One of ``fail``, ``degraded``, ``pass_indirect``, ``pass`` (lowercase),
> ordered ``fail`` < ``degraded`` < ``pass_indirect`` < ``pass``. Defined as a
> total, deterministic, severity-independent function of the predicate,
> evaluated as the minimum under that order of three independent conditions
> rather than as a cascade, because worst-wins rather than evaluation order is
> the rule.

The three conditions, quoted:

1. "The first condition holds when any ``attackResults`` row carries a
   containment-observed label from the carried caught set
   (``observationVocabulary.caught``), a label outside the carried
   ``observationVocabulary.labels`` (fail-closed), or a missing or
   out-of-vocabulary ``basis``, ``method`` or ``attribution`` (fail-closed),
   and it contributes ``fail``."
2. "The second holds when ``coverage.outOfScope`` or
   ``coverage.routedElsewhere`` is non-empty, and it contributes ``degraded``."
3. "The third holds when any clean row, meaning a row whose
   ``containmentObserved`` is in the carried labels and not in the carried
   caught set, carries a ``basis`` other than ``substrate`` or a ``method``
   other than ``intercepted``, and it contributes ``pass_indirect``."

"A condition that does not hold contributes ``pass``."

Two properties of this function are load-bearing and are implemented as such.
It is a minimum over three *independent* conditions, not a cascade: each is
evaluated whatever the others decide, so the reasons are complete even when the
token is already ``fail``. And per Parsing Rules it "is a function of the
carried predicate alone: it never reads ``observationRecords``,
signature-verification outcomes, or any consumer trust decision" -- so this
module takes the predicate and nothing else, and cannot be handed a key, a
record set or a policy.

``attribution`` "enters the recompute through the fail-closed arm of the first
condition and nowhere else". ``actualLayer`` enters it not at all: a row missing
that member is malformed under the framework's parsing rules, "rather than the
row forcing ``fail``", and that is the well-formedness gate's business.
"""

__all__ = [
    "ATTRIBUTION_VALUES",
    "BASIS_VALUES",
    "METHOD_VALUES",
    "RESULT_ORDER",
    "Recompute",
    "is_clean_row",
    "recompute_result",
]

#: Ascending. The minimum under this order is the result.
RESULT_ORDER = ("fail", "degraded", "pass_indirect", "pass")

#: "all three vocabularies are closed"
BASIS_VALUES = frozenset({"substrate", "artifact"})
METHOD_VALUES = frozenset({"intercepted", "reconstructed"})
ATTRIBUTION_VALUES = frozenset({"pinned", "paired"})

_RANK = {token: index for index, token in enumerate(RESULT_ORDER)}


class Recompute:
    """The recomputed token, with what each condition contributed and why."""

    __slots__ = ("result", "contributions", "reasons")

    def __init__(self, result, contributions, reasons):
        self.result = result
        self.contributions = tuple(contributions)
        self.reasons = tuple(reasons)

    def __repr__(self):
        return "Recompute(result=%r, contributions=%r)" % (
            self.result,
            self.contributions,
        )

    def __eq__(self, other):
        if isinstance(other, Recompute):
            return (
                self.result == other.result
                and self.contributions == other.contributions
            )
        return NotImplemented


def _vocabulary(predicate):
    """The carried label and caught sets.

    Absent or malformed vocabulary yields empty sets, which makes every label
    "outside the carried labels" and drives the first condition to ``fail``.
    That is the fail-closed direction, and it keeps the recompute total on any
    input, as the definition requires. A statement that reaches this state is
    separately malformed; the recompute does not depend on that being caught
    first.
    """
    environment = predicate.get("observationEnvironment")
    vocabulary = environment.get("observationVocabulary") if isinstance(environment, dict) else None
    if not isinstance(vocabulary, dict):
        return frozenset(), frozenset()
    labels = vocabulary.get("labels")
    caught = vocabulary.get("caught")
    labels = frozenset(x for x in labels if isinstance(x, str)) if isinstance(labels, list) else frozenset()
    caught = frozenset(x for x in caught if isinstance(x, str)) if isinstance(caught, list) else frozenset()
    return labels, caught


def is_clean_row(row, labels, caught):
    """"a row whose ``containmentObserved`` is in the carried labels and not in
    the carried caught set"."""
    observed = row.get("containmentObserved") if isinstance(row, dict) else None
    return observed in labels and observed not in caught


def _rows(predicate):
    rows = predicate.get("attackResults")
    return rows if isinstance(rows, list) else []


def _condition_one(rows, labels, caught):
    reasons = []
    for index, row in enumerate(rows):
        if not isinstance(row, dict):
            reasons.append("attackResults[%d] is not an object" % index)
            continue
        observed = row.get("containmentObserved")
        if observed in caught:
            reasons.append(
                "attackResults[%d] carries the caught label %r" % (index, observed)
            )
        elif observed not in labels:
            reasons.append(
                "attackResults[%d] carries %r, which is outside the carried "
                "labels" % (index, observed)
            )
        for member, allowed in (
            ("basis", BASIS_VALUES),
            ("method", METHOD_VALUES),
            ("attribution", ATTRIBUTION_VALUES),
        ):
            value = row.get(member)
            if value is None:
                reasons.append("attackResults[%d] is missing %s" % (index, member))
            elif value not in allowed:
                reasons.append(
                    "attackResults[%d] carries %s %r, outside its closed "
                    "vocabulary" % (index, member, value)
                )
    return ("fail" if reasons else "pass"), reasons


def _condition_two(predicate):
    coverage = predicate.get("coverage")
    reasons = []
    if isinstance(coverage, dict):
        for member in ("outOfScope", "routedElsewhere"):
            gap = coverage.get(member)
            if gap:
                reasons.append(
                    "coverage.%s discloses %d class(es)" % (member, len(gap))
                )
    return ("degraded" if reasons else "pass"), reasons


def _condition_three(rows, labels, caught):
    reasons = []
    for index, row in enumerate(rows):
        if not isinstance(row, dict) or not is_clean_row(row, labels, caught):
            continue
        basis = row.get("basis")
        method = row.get("method")
        if basis != "substrate" or method != "intercepted":
            reasons.append(
                "clean attackResults[%d] rests on basis %r, method %r"
                % (index, basis, method)
            )
    return ("pass_indirect" if reasons else "pass"), reasons


def recompute_result(predicate):
    """Recompute ``result`` from the carried predicate.

    Returns a :class:`Recompute`. Never raises on shape: the definition calls
    this a total function of the predicate, so malformed input resolves
    fail-closed rather than throwing.
    """
    if not isinstance(predicate, dict):
        return Recompute("fail", ("fail", "pass", "pass"), ("predicate is not an object",))

    labels, caught = _vocabulary(predicate)
    rows = _rows(predicate)

    # Independent, not a cascade: all three are evaluated every time.
    first, why_first = _condition_one(rows, labels, caught)
    second, why_second = _condition_two(predicate)
    third, why_third = _condition_three(rows, labels, caught)

    contributions = (first, second, third)
    result = min(contributions, key=lambda token: _RANK[token])
    return Recompute(result, contributions, why_first + why_second + why_third)
