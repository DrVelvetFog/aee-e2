"""Statement well-formedness: stage one, step one.

Spec basis (head 25ac8581), Parsing Rules: stage one is byte-pure, and its
first step is "statement well-formedness, including the vocabulary rules and,
for substrate-carrying statements, run-binding derivability". Step three, the
``result`` recompute, is checked here too, because "a ``result`` the recompute
does not reproduce makes the attestation invalid" and the comparison needs no
input this module does not already hold.

Coverage validity -- step two -- reads record payloads and lives in its own
module. Nothing here decodes a payload.

Every check is a function of the carried statement. A finding means the
attestation is invalid; findings are accumulated rather than raised at the first
one, so a report can say everything that is wrong with a statement instead of
only the first thing.
"""

from .bindings import POSTURE_VALUES, corpus_digest, vocabulary_digest
from .findings import Finding
from .ijson import is_bmp_only
from .jcs import sort_utf16
from .result import (
    ATTRIBUTION_VALUES,
    BASIS_VALUES,
    METHOD_VALUES,
    RESULT_ORDER,
    is_clean_row,
    recompute_result,
)
from .timestamps import is_admissible

__all__ = ["PREDICATE_TYPE", "STATEMENT_TYPE", "check_wellformed"]

STATEMENT_TYPE = "https://in-toto.io/Statement/v1"
PREDICATE_TYPE = (
    "https://in-toto.io/attestation/adversarial-execution-evidence/v0.7"
)

_ENVIRONMENT_MEMBERS = (
    "substrate",
    "corpus",
    "catchPolicy",
    "networkPosture",
    "observationVocabulary",
)
_ROW_MEMBERS = (
    "attackId",
    "containmentObserved",
    "basis",
    "method",
    "attribution",
    "actualLayer",
)
_HEX = set("0123456789abcdef")


def _is_lower_64_hex(value):
    return isinstance(value, str) and len(value) == 64 and set(value) <= _HEX


def _digest_of(node):
    if not isinstance(node, dict):
        return None
    digest = node.get("digest")
    if not isinstance(digest, dict):
        return None
    return digest.get("sha256")


def _check_sorted_unique_bmp(values, where, out):
    """The three array rules the vocabulary and expectedPayloads share."""
    if len(set(values)) != len(values):
        out.append(Finding("wf-array-duplicate", "%s carries a duplicate entry" % where))
    if list(values) != sort_utf16(values):
        out.append(
            Finding(
                "wf-array-order",
                "%s is not sorted ascending by UTF-16 code unit" % where,
            )
        )


def _check_statement_shape(statement, out):
    if statement.get("_type") != STATEMENT_TYPE:
        out.append(
            Finding("wf-statement-type", "_type is not %s" % STATEMENT_TYPE)
        )
    if statement.get("predicateType") != PREDICATE_TYPE:
        out.append(
            Finding(
                "wf-predicate-type",
                "predicateType is not %s" % PREDICATE_TYPE,
            )
        )
    subject = statement.get("subject")
    if not isinstance(subject, list) or not subject:
        out.append(Finding("wf-subject", "subject is absent or empty"))
    elif not _is_lower_64_hex(_digest_of(subject[0])):
        out.append(
            Finding(
                "wf-subject",
                "subject[0].digest.sha256 is absent or not lowercase 64-hex",
            )
        )


def _check_vocabulary(vocabulary, out):
    """labels and caught: sorted, duplicate-free, BMP-only, caught a subset."""
    labels = vocabulary.get("labels")
    caught = vocabulary.get("caught")
    for name, array in (("labels", labels), ("caught", caught)):
        if not isinstance(array, list) or not all(isinstance(x, str) for x in array):
            out.append(
                Finding(
                    "wf-vocabulary-shape",
                    "observationVocabulary.%s is absent or not an array of strings"
                    % name,
                )
            )
            return
        _check_sorted_unique_bmp(array, "observationVocabulary.%s" % name, out)
        if not all(is_bmp_only(x) for x in array):
            out.append(
                Finding(
                    "wf-vocabulary-bmp",
                    "observationVocabulary.%s carries an entry outside the BMP"
                    % name,
                )
            )
    if not set(caught) <= set(labels):
        out.append(
            Finding(
                "wf-caught-subset",
                "observationVocabulary.caught is not a subset of labels",
            )
        )
    carried = _digest_of(vocabulary)
    if carried != vocabulary_digest(labels, caught):
        out.append(
            Finding(
                "wf-vocabulary-digest",
                "observationVocabulary.digest does not equal the recompute over "
                "the carried labels and caught arrays",
            )
        )


def _declared_attacks(manifest):
    """Map attackId -> list of classes declaring it."""
    declared = {}
    classes = manifest.get("classes")
    if not isinstance(classes, dict):
        return declared
    for class_code, attacks in classes.items():
        if not isinstance(attacks, list):
            continue
        for attack in attacks:
            declared.setdefault(attack, []).append(class_code)
    return declared


def _check_corpus(corpus, out):
    manifest = corpus.get("manifest")
    if not isinstance(manifest, dict):
        out.append(Finding("wf-manifest-shape", "corpus.manifest is absent"))
        return {}
    classes = manifest.get("classes")
    if not isinstance(classes, dict):
        out.append(
            Finding("wf-manifest-shape", "corpus.manifest.classes is absent")
        )
        return {}

    declared = _declared_attacks(manifest)
    if not declared:
        # "a manifest declaring zero attack identifiers makes the statement
        # malformed" -- phrased over identifiers, not classes, so an empty
        # classes object and a named class with an empty array are both caught.
        out.append(
            Finding(
                "wf-manifest-floor",
                "corpus.manifest declares no attack identifier across its classes",
            )
        )
    for attack, owners in sorted(declared.items()):
        if len(owners) > 1:
            out.append(
                Finding(
                    "wf-manifest-class-overlap",
                    "attackId %r appears under %d classes" % (attack, len(owners)),
                )
            )

    if _digest_of(corpus) != corpus_digest(manifest):
        out.append(
            Finding(
                "wf-corpus-digest",
                "corpus.digest does not equal the recompute over the carried "
                "manifest",
            )
        )

    expected = manifest.get("expectedPayloads")
    if expected is not None:
        if not isinstance(expected, dict):
            out.append(
                Finding(
                    "wf-expected-payloads",
                    "corpus.manifest.expectedPayloads is not an object",
                )
            )
        else:
            for attack, values in sorted(expected.items()):
                where = "expectedPayloads[%r]" % attack
                if attack not in declared:
                    out.append(
                        Finding(
                            "wf-expected-payloads",
                            "%s names an attackId the manifest does not declare"
                            % where,
                        )
                    )
                if not isinstance(values, list) or not values:
                    out.append(
                        Finding(
                            "wf-expected-payloads", "%s is absent or empty" % where
                        )
                    )
                    continue
                if not all(_is_lower_64_hex(v) for v in values):
                    out.append(
                        Finding(
                            "wf-expected-payloads",
                            "%s carries an entry that is not lowercase 64-hex" % where,
                        )
                    )
                    continue
                _check_sorted_unique_bmp(values, where, out)
    return declared


def _check_environment(predicate, rows, out):
    environment = predicate.get("observationEnvironment")
    if not isinstance(environment, dict):
        out.append(
            Finding("wf-missing-member", "observationEnvironment is absent")
        )
        return {}

    for member in _ENVIRONMENT_MEMBERS:
        if not isinstance(environment.get(member), dict):
            out.append(
                Finding(
                    "wf-missing-member",
                    "observationEnvironment.%s is absent" % member,
                )
            )

    posture = environment.get("networkPosture")
    if isinstance(posture, dict):
        token = posture.get("posture")
        if not isinstance(token, str) or token not in POSTURE_VALUES:
            out.append(
                Finding(
                    "wf-posture-vocabulary",
                    "networkPosture.posture is absent, is not a string, or is "
                    "outside the registered set",
                )
            )

    vocabulary = environment.get("observationVocabulary")
    if isinstance(vocabulary, dict):
        _check_vocabulary(vocabulary, out)

    declared = {}
    corpus = environment.get("corpus")
    if isinstance(corpus, dict):
        declared = _check_corpus(corpus, out)

    # "A sixth member, runEntropy ..., is required exactly when any row carries
    # basis: substrate."
    has_substrate = any(
        isinstance(row, dict) and row.get("basis") == "substrate" for row in rows
    )
    if has_substrate and not isinstance(environment.get("runEntropy"), dict):
        out.append(
            Finding(
                "wf-run-entropy",
                "runEntropy is absent while a row carries basis: substrate",
            )
        )
    return declared


def _check_rows(predicate, rows, declared, out):
    records = predicate.get("observationRecords")
    record_count = len(records) if isinstance(records, list) else 0
    labels, caught = _carried_vocabulary(predicate)

    seen = {}
    for index, row in enumerate(rows):
        where = "attackResults[%d]" % index
        if not isinstance(row, dict):
            out.append(Finding("wf-row-shape", "%s is not an object" % where))
            continue
        for member in _ROW_MEMBERS:
            if member not in row:
                out.append(
                    Finding("wf-row-member", "%s is missing %s" % (where, member))
                )
        for member, allowed in (
            ("basis", BASIS_VALUES),
            ("method", METHOD_VALUES),
            ("attribution", ATTRIBUTION_VALUES),
        ):
            value = row.get(member)
            if value is not None and value not in allowed:
                out.append(
                    Finding(
                        "wf-row-vocabulary",
                        "%s carries %s %r, outside its closed vocabulary"
                        % (where, member, value),
                    )
                )

        attack = row.get("attackId")
        if attack in seen:
            # "uniqueness is enforced separately, before that comparison, not
            # left to it": a duplicate would collapse under set semantics.
            out.append(
                Finding(
                    "wf-duplicate-attack-id",
                    "%s repeats attackId %r from attackResults[%d]"
                    % (where, attack, seen[attack]),
                )
            )
        else:
            seen[attack] = index
        if declared and attack is not None and attack not in declared:
            out.append(
                Finding(
                    "wf-unknown-attack-id",
                    "%s carries attackId %r, which the manifest does not declare"
                    % (where, attack),
                )
            )

        refs = row.get("observationRefs")
        if refs is not None:
            if not isinstance(refs, list):
                out.append(
                    Finding(
                        "wf-observation-refs", "%s.observationRefs is not an array" % where
                    )
                )
            else:
                for ref in refs:
                    if not isinstance(ref, int) or isinstance(ref, bool) or not 0 <= ref < record_count:
                        out.append(
                            Finding(
                                "wf-observation-ref-range",
                                "%s.observationRefs names %r, which is out of range "
                                "for the %d carried record(s)"
                                % (where, ref, record_count),
                            )
                        )

        # "On a row whose containmentObserved label is from the carried labels
        # but not in the caught set (a clean row: nothing acted), the producer
        # MUST emit the literal string none."
        if is_clean_row(row, labels, caught) and row.get("actualLayer") != "none":
            out.append(
                Finding(
                    "wf-clean-row-actual-layer",
                    "clean %s carries actualLayer %r rather than the literal "
                    "'none'" % (where, row.get("actualLayer")),
                )
            )


def _carried_vocabulary(predicate):
    environment = predicate.get("observationEnvironment")
    vocabulary = (
        environment.get("observationVocabulary") if isinstance(environment, dict) else None
    )
    if not isinstance(vocabulary, dict):
        return frozenset(), frozenset()
    labels = vocabulary.get("labels")
    caught = vocabulary.get("caught")
    return (
        frozenset(labels) if isinstance(labels, list) else frozenset(),
        frozenset(caught) if isinstance(caught, list) else frozenset(),
    )


def _check_coverage(predicate, rows, declared, out):
    coverage = predicate.get("coverage")
    if not isinstance(coverage, dict):
        out.append(Finding("wf-missing-member", "coverage is absent"))
        return
    assessed = coverage.get("assessedClasses")
    out_of_scope = coverage.get("outOfScope")
    routed = coverage.get("routedElsewhere")
    if not isinstance(assessed, list) or not all(isinstance(c, str) for c in assessed):
        out.append(
            Finding("wf-coverage-shape", "coverage.assessedClasses is absent or not an array of strings")
        )
        return
    for name, gap in (("outOfScope", out_of_scope), ("routedElsewhere", routed)):
        if not isinstance(gap, dict):
            out.append(
                Finding("wf-coverage-shape", "coverage.%s is absent or not an object" % name)
            )
            return

    environment = predicate.get("observationEnvironment")
    corpus = environment.get("corpus") if isinstance(environment, dict) else None
    manifest = corpus.get("manifest") if isinstance(corpus, dict) else None
    classes = manifest.get("classes") if isinstance(manifest, dict) else None
    if not isinstance(classes, dict):
        return

    # "The three sets are a disjoint partition of the manifest's classes: a
    # class appears in exactly one of assessedClasses, outOfScope,
    # routedElsewhere (a move, not a copy)."
    membership = {}
    for name, names in (
        ("assessedClasses", assessed),
        ("outOfScope", list(out_of_scope)),
        ("routedElsewhere", list(routed)),
    ):
        for class_code in names:
            membership.setdefault(class_code, []).append(name)
    for class_code, places in sorted(membership.items()):
        if len(places) > 1:
            out.append(
                Finding(
                    "wf-coverage-partition",
                    "class %r appears in %s" % (class_code, " and ".join(places)),
                )
            )
    for class_code in sorted(classes):
        if class_code not in membership:
            out.append(
                Finding(
                    "wf-coverage-partition",
                    "manifest class %r appears in none of the three coverage sets"
                    % class_code,
                )
            )

    # "Coverage integrity is checked at attack granularity: the union of
    # attackIds for the assessed classes must exactly equal the manifest's."
    expected = set()
    for class_code in assessed:
        entry = classes.get(class_code)
        if isinstance(entry, list):
            expected.update(entry)
    carried = {row.get("attackId") for row in rows if isinstance(row, dict)}
    if carried != expected:
        missing = sorted(x for x in expected - carried if x is not None)
        extra = sorted(x for x in carried - expected if x is not None)
        out.append(
            Finding(
                "wf-coverage-integrity",
                "the carried rows and the assessed classes' attack identifiers "
                "differ: %d not reported, %d not declared"
                % (len(missing), len(extra)),
                where="missing=%r extra=%r" % (missing, extra),
            )
        )


def check_wellformed(statement):
    """Every well-formedness finding for ``statement``, in check order."""
    out = []
    if not isinstance(statement, dict):
        return [Finding("wf-statement-shape", "statement is not an object")]

    _check_statement_shape(statement, out)

    predicate = statement.get("predicate")
    if not isinstance(predicate, dict):
        out.append(Finding("wf-missing-member", "predicate is absent"))
        return out

    rows = predicate.get("attackResults")
    if not isinstance(rows, list):
        out.append(Finding("wf-missing-member", "attackResults is absent or not an array"))
        rows = []

    declared = _check_environment(predicate, rows, out)
    _check_rows(predicate, rows, declared, out)
    _check_coverage(predicate, rows, declared, out)

    issued_at = predicate.get("issuedAt")
    if not is_admissible(issued_at):
        out.append(
            Finding(
                "wf-timestamp-profile",
                "issuedAt is absent, is not RFC 3339, or is RFC 3339 outside the "
                "pinned profile",
            )
        )

    records = predicate.get("observationRecords")
    if isinstance(records, list) and records and "batchRoot" not in predicate:
        out.append(
            Finding(
                "wf-batch-root",
                "batchRoot is absent while observationRecords is non-empty",
            )
        )

    does_not_assert = predicate.get("doesNotAssert")
    if does_not_assert is not None and (
        not isinstance(does_not_assert, list)
        or not all(isinstance(x, str) for x in does_not_assert)
    ):
        out.append(
            Finding("wf-does-not-assert", "doesNotAssert is not an array of strings")
        )

    carried_result = predicate.get("result")
    if carried_result not in RESULT_ORDER:
        out.append(
            Finding(
                "wf-result-token",
                "result is absent or outside the four registered tokens",
            )
        )
    else:
        recomputed = recompute_result(predicate)
        if carried_result != recomputed.result:
            out.append(
                Finding(
                    "wf-result-recompute",
                    "result carries %r; the recompute over the carried predicate "
                    "gives %r" % (carried_result, recomputed.result),
                    where="; ".join(recomputed.reasons) or None,
                )
            )
    return out
