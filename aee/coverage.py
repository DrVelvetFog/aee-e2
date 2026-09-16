"""Coverage validity: stage one, step two.

Spec basis (head 25ac8581):

> **Coverage validity (derived from carried bytes; a violation is malformed).**
> For every ``basis: substrate`` row, the following MUST hold or the attestation
> is invalid ... These read record payloads but never signatures or consumer
> policy, so they are a pure function of the carried statement, and that is what
> makes them runnable by a consumer holding no keys. It is also their limit: a
> violation here is conclusive, since no signature can rescue a statement that
> does not hang together, but the absence of a violation concludes nothing on
> its own.

Five requirements hold per ``basis: substrate`` row and six more hold on the
statement or on every row. All eleven are consumption preconditions: "a consumer
that consumes ``result``, credits any row, or applies either strength ordering
MUST first evaluate them".

Nothing here reads a signature. The ``signatures`` member is checked for
presence, because ``observationRecords`` requires at least one entry, and never
verified -- that is stage two.
"""

from .bindings import run_binding_digest
from .dsse import DSSEError, decode_payload, pae_for_record
from .findings import Finding
from .ijson import IJSONError, is_bmp_only, loads
from .jcs import canonicalize, sort_utf16
from .merkle import MerkleError, root_for_records
from .observed_set import OBSERVED_KINDS, observed_set_from_paes
from .result import ATTRIBUTION_VALUES, METHOD_VALUES, is_clean_row
from .timestamps import is_admissible, parse_instant

__all__ = [
    "COVERING_KINDS",
    "SEALED_POSTURE_IS_A_KIND_CONSTRAINT",
    "check_coverage_validity",
]

#: Drift switch. The head (25ac8581) states the sealed record's aeePostureDigest
#: equality as a constraint *of the kind*, which coverage validity evaluates
#: against every carried record that binds to the run, resolved or not. The
#: corpus-pinned text (0dbe10bc) states the same equality only as a condition of
#: covering a clean row. Set False for the 0dbe10bc reading. See DRIFT.md.
SEALED_POSTURE_IS_A_KIND_CONSTRAINT = True

#: "whose payload aeeKind names a covering kind -- interception, arming,
#: sealed, examination"
COVERING_KINDS = ("interception", "arming", "sealed", "examination")

#: "reconstructed is weaker than intercepted"
_METHOD_STRENGTH = {"reconstructed": 0, "intercepted": 1}

_RESERVED = ("aeeRunBinding", "aeeKind", "aeeMethod")
_HEX = set("0123456789abcdef")


def _is_lower_64_hex(value):
    return isinstance(value, str) and len(value) == 64 and set(value) <= _HEX


def _is_integer(value):
    return isinstance(value, int) and not isinstance(value, bool)


def _check_hex_array(values, where, out, require_non_empty=True):
    if not isinstance(values, list) or not all(isinstance(v, str) for v in values):
        out.append(Finding("cv-record-member", "%s is absent or not an array of strings" % where))
        return False
    if require_non_empty and not values:
        out.append(Finding("cv-record-member", "%s is empty" % where))
        return False
    if len(set(values)) != len(values):
        out.append(Finding("cv-array-duplicate", "%s carries a duplicate entry" % where))
        return False
    if list(values) != sort_utf16(values):
        out.append(Finding("cv-array-order", "%s is not sorted ascending by UTF-16 code unit" % where))
        return False
    if not all(_is_lower_64_hex(v) for v in values):
        out.append(Finding("cv-record-member", "%s carries an entry that is not lowercase 64-hex" % where))
        return False
    return True


def _check_identifier_array(values, declared, where, out):
    if not isinstance(values, list) or not all(isinstance(v, str) for v in values):
        out.append(Finding("cv-record-member", "%s is absent or not an array of strings" % where))
        return False
    ok = True
    if len(set(values)) != len(values):
        out.append(Finding("cv-array-duplicate", "%s carries a duplicate entry" % where))
        ok = False
    if list(values) != sort_utf16(values):
        out.append(Finding("cv-array-order", "%s is not sorted ascending by UTF-16 code unit" % where))
        ok = False
    unknown = [v for v in values if v not in declared]
    if unknown:
        out.append(
            Finding(
                "cv-record-member",
                "%s names %d identifier(s) the carried manifest does not declare"
                % (where, len(unknown)),
            )
        )
        ok = False
    return ok




#: "aeeChainScope ... a closed vocabulary ... subject to subject[0].digest.sha256,
#: corpus to observationEnvironment.corpus.digest, and networkPosture to
#: networkPosture.digest.sha256"
CHAIN_SCOPE_TOKENS = frozenset({"subject", "corpus", "networkPosture"})

_CHAIN_MEMBERS = ("aeeRunSeq", "aeePrevRunBinding", "aeeChainScope")


def _check_chain_members(payload, where, out):
    """The chain-of-runs syntax rules, on an arming record.

    > A violation of the syntax rules (a non-positive or non-integer
    > ``aeeRunSeq``, a malformed ``aeePrevRunBinding``, a missing
    > ``aeeChainScope`` when the sequence is present, a non-array
    > ``aeeChainScope``, an array carrying a token outside the registered
    > vocabulary, an array not in canonical order ..., or any of the three
    > present without ``aeeRunSeq``) is handled as any reserved-member
    > violation: the record covers nothing.

    Syntax and nothing else: "within one attestation these members are
    syntax-checked in the reserved-member walk and nothing else normative reads
    them". The chain's value is across attestations, as consumer policy, and a
    verifier holding one statement has no second one to compare against.
    """
    present = [name for name in _CHAIN_MEMBERS if name in payload]
    if not present:
        return
    if "aeeRunSeq" not in payload:
        out.append(
            Finding(
                "cv-chain-members",
                "%s carries %s without aeeRunSeq" % (where, ", ".join(present)),
            )
        )
        return

    sequence = payload["aeeRunSeq"]
    if not _is_integer(sequence) or sequence < 1:
        out.append(
            Finding(
                "cv-chain-members",
                "%s aeeRunSeq is not a positive integer" % where,
            )
        )

    scope = payload.get("aeeChainScope")
    if "aeeChainScope" not in payload:
        out.append(
            Finding(
                "cv-chain-members",
                "%s carries aeeRunSeq with no aeeChainScope" % where,
            )
        )
    elif not isinstance(scope, list) or not all(isinstance(x, str) for x in scope):
        out.append(
            Finding("cv-chain-members", "%s aeeChainScope is not an array of strings" % where)
        )
    else:
        if not set(scope) <= CHAIN_SCOPE_TOKENS:
            out.append(
                Finding(
                    "cv-chain-members",
                    "%s aeeChainScope carries a token outside the registered vocabulary" % where,
                )
            )
        if len(set(scope)) != len(scope):
            out.append(
                Finding("cv-array-duplicate", "%s aeeChainScope carries a duplicate entry" % where)
            )
        elif list(scope) != sort_utf16(scope):
            out.append(
                Finding("cv-array-order", "%s aeeChainScope is not in canonical order" % where)
            )

    # "absent exactly when aeeRunSeq is 1"
    previous = payload.get("aeePrevRunBinding")
    if _is_integer(sequence) and sequence == 1:
        if "aeePrevRunBinding" in payload:
            out.append(
                Finding(
                    "cv-chain-members",
                    "%s carries aeePrevRunBinding on the genesis run" % where,
                )
            )
    elif _is_integer(sequence) and sequence > 1:
        if not _is_lower_64_hex(previous):
            out.append(
                Finding(
                    "cv-chain-members",
                    "%s aeePrevRunBinding is absent or not lowercase 64-hex" % where,
                )
            )

class _Record:
    """One carried record, reduced to what the gate reads."""

    __slots__ = ("index", "envelope", "payload", "kind", "method", "binds", "kind_ok", "readable")

    def __init__(self, index, envelope):
        self.index = index
        self.envelope = envelope
        self.payload = None
        self.kind = None
        self.method = None
        self.binds = False
        self.kind_ok = False
        self.readable = False

    @property
    def where(self):
        return "observationRecords[%d]" % self.index


def _read_payload(record, out, report):
    """Parse one record's payload under the rules a covering record must meet.

    > Any record used to cover a ``basis: substrate`` row MUST carry a JSON
    > object payload that is canonical per RFC 8785 and valid I-JSON per
    > RFC 7493 ..., whose media type ends in ``+json``, and which carries these
    > reserved members as top-level fields; a record whose payload is not so
    > parseable, or whose media type is not ``+json``, covers nothing.

    ``report`` controls whether failures are recorded. A record that no rule
    reaches is parsed silently, so an unreadable payload on an unreferenced
    record of an unrecognised kind is not turned into a finding.
    """
    envelope = record.envelope
    if not isinstance(envelope, dict):
        if report:
            out.append(Finding("cv-record-shape", "%s is not an object" % record.where))
        return
    signatures = envelope.get("signatures")
    if not isinstance(signatures, list) or not signatures:
        if report:
            out.append(
                Finding("cv-record-signatures", "%s carries no signatures entry" % record.where)
            )
    payload_type = envelope.get("payloadType")
    if not isinstance(payload_type, str) or not payload_type.endswith("+json"):
        if report:
            out.append(
                Finding("cv-media-type", "%s media type does not end in +json" % record.where)
            )
        return
    try:
        raw = decode_payload(envelope.get("payload"))
    except DSSEError as exc:
        if report:
            out.append(Finding("cv-payload-parse", "%s payload: %s" % (record.where, exc)))
        return
    try:
        parsed = loads(raw)
    except IJSONError as exc:
        if report:
            out.append(Finding("cv-payload-parse", "%s payload: %s" % (record.where, exc)))
        return
    if not isinstance(parsed, dict):
        if report:
            out.append(Finding("cv-payload-parse", "%s payload is not a JSON object" % record.where))
        return
    if raw != canonicalize(parsed):
        if report:
            out.append(
                Finding("cv-payload-canonical", "%s payload bytes are not RFC 8785 canonical" % record.where)
            )
        return
    if not all(is_bmp_only(name) for name in parsed):
        if report:
            out.append(
                Finding("cv-payload-bmp", "%s payload carries a member name outside the BMP" % record.where)
            )
        return
    missing = [name for name in _RESERVED if not isinstance(parsed.get(name), str)]
    if missing:
        if report:
            out.append(
                Finding(
                    "cv-payload-reserved",
                    "%s payload is missing reserved member(s) %s" % (record.where, ", ".join(missing)),
                )
            )
        return
    record.payload = parsed
    record.kind = parsed["aeeKind"]
    record.method = parsed["aeeMethod"]
    record.readable = True


def _check_kind(record, context, out):
    """Every constraint of the record's declared kind."""
    payload = record.payload
    where = record.where
    kind = record.kind
    before = len(out)

    if kind == "interception":
        _check_hex_array(payload.get("aeePayloadCommitment"), "%s aeePayloadCommitment" % where, out)
    elif kind == "arming":
        _check_chain_members(payload, where, out)
        armed_at = payload.get("armedAt")
        if not is_admissible(armed_at):
            out.append(Finding("cv-record-member", "%s armedAt is absent or outside the pinned timestamp profile" % where))
        elif context["issued_at"] is not None and parse_instant(armed_at) > context["issued_at"]:
            out.append(Finding("cv-armed-after-issued", "%s armedAt is later than issuedAt" % where))
        if payload.get("aeePostureDigest") != context["posture_digest"]:
            out.append(Finding("cv-posture-digest", "%s aeePostureDigest does not equal the pinned networkPosture digest" % where))
        _check_identifier_array(payload.get("aeeAssessedAttacks"), context["declared"], "%s aeeAssessedAttacks" % where, out)
        if record.method != "intercepted":
            out.append(Finding("cv-record-method", "%s is an arming record whose aeeMethod is not intercepted" % where))
    elif kind == "sealed":
        # R4. The conditions stated at the kind's class definition are
        # constraints of the kind, so the universal partner evaluates them
        # against every carried binding seal, resolved or not: "a substrate
        # signs a sealed record reporting its moat down, the producer carries
        # that record and points the row at a second seal, and the run reads
        # clean with the record that says otherwise sitting in the statement
        # and inside batchRoot."
        if payload.get("aeeStillArmed") is not True:
            out.append(Finding("cv-seal-covers-nothing", "%s aeeStillArmed is absent, not a boolean, or false" % where))
        drop_count = payload.get("aeeDropCount")
        if not _is_integer(drop_count):
            out.append(Finding("cv-record-member", "%s aeeDropCount is absent or not an integer" % where))
        elif drop_count != 0:
            bound = payload.get("aeeDropBound")
            if not _is_integer(bound):
                out.append(Finding("cv-seal-covers-nothing", "%s carries a non-zero aeeDropCount with no integer aeeDropBound" % where))
            elif drop_count > bound:
                out.append(Finding("cv-seal-covers-nothing", "%s aeeDropCount exceeds its declared aeeDropBound" % where))
        elif "aeeDropBound" in payload and not _is_integer(payload["aeeDropBound"]):
            out.append(Finding("cv-record-member", "%s aeeDropBound is not an integer" % where))
        if not isinstance(payload.get("aeePostureDigest"), str):
            out.append(Finding("cv-record-member", "%s aeePostureDigest is absent" % where))
        elif SEALED_POSTURE_IS_A_KIND_CONSTRAINT and payload["aeePostureDigest"] != context["posture_digest"]:
            # Drift hunk 1333c1392,1393. See DRIFT.md.
            out.append(Finding("cv-posture-digest", "%s aeePostureDigest does not equal the pinned networkPosture digest" % where))
        if not _is_lower_64_hex(payload.get("aeeObservedSet")):
            out.append(Finding("cv-record-member", "%s aeeObservedSet is absent or not lowercase 64-hex" % where))
        _check_identifier_array(payload.get("aeeObservedAttacks"), context["declared"], "%s aeeObservedAttacks" % where, out)
        if record.method != "intercepted":
            out.append(Finding("cv-record-method", "%s is a sealed record whose aeeMethod is not intercepted" % where))
    elif kind == "examination":
        if record.method != "reconstructed":
            out.append(Finding("cv-record-method", "%s is an examination record whose aeeMethod is not reconstructed" % where))

    record.kind_ok = len(out) == before


def _seal_covers(record, row_arming_digests, context):
    """The covering conditions stated at the sealed class definition.

    > A ``sealed`` record covers no clean row unless its ``aeeStillArmed`` is
    > ``true``, its ``aeeDropCount`` is zero or does not exceed an
    > ``aeeDropBound`` declared in the same signed payload, and its
    > ``aeePostureDigest`` equals the pinned ``networkPosture`` digest and the
    > ``aeePostureDigest`` of every ``arming`` record the row resolves
    """
    payload = record.payload
    if payload is None or payload.get("aeeStillArmed") is not True:
        return False
    drop_count = payload.get("aeeDropCount")
    if not _is_integer(drop_count):
        return False
    if drop_count != 0:
        bound = payload.get("aeeDropBound")
        if not _is_integer(bound) or drop_count > bound:
            return False
    posture = payload.get("aeePostureDigest")
    if posture != context["posture_digest"]:
        return False
    return all(posture == digest for digest in row_arming_digests)


def check_coverage_validity(statement):
    """Every coverage-validity finding for ``statement``, in check order."""
    out = []
    if not isinstance(statement, dict):
        return out
    predicate = statement.get("predicate")
    if not isinstance(predicate, dict):
        return out
    rows = predicate.get("attackResults")
    rows = rows if isinstance(rows, list) else []
    records = predicate.get("observationRecords")
    records = records if isinstance(records, list) else []

    environment = predicate.get("observationEnvironment")
    environment = environment if isinstance(environment, dict) else {}
    vocabulary = environment.get("observationVocabulary")
    vocabulary = vocabulary if isinstance(vocabulary, dict) else {}
    labels = frozenset(vocabulary.get("labels") or [])
    caught = frozenset(vocabulary.get("caught") or [])

    corpus = environment.get("corpus") if isinstance(environment.get("corpus"), dict) else {}
    manifest = corpus.get("manifest") if isinstance(corpus.get("manifest"), dict) else {}
    classes = manifest.get("classes") if isinstance(manifest.get("classes"), dict) else {}
    declared = set()
    for attacks in classes.values():
        if isinstance(attacks, list):
            declared.update(attacks)
    expected_payloads = manifest.get("expectedPayloads")
    expected_payloads = expected_payloads if isinstance(expected_payloads, dict) else {}

    posture = environment.get("networkPosture")
    posture_digest = None
    if isinstance(posture, dict) and isinstance(posture.get("digest"), dict):
        posture_digest = posture["digest"].get("sha256")

    try:
        binding = run_binding_digest(predicate, statement.get("subject"))
    except Exception:
        binding = None

    context = {
        "declared": declared,
        "posture_digest": posture_digest,
        "issued_at": parse_instant(predicate.get("issuedAt")),
    }

    substrate_rows = [
        (index, row)
        for index, row in enumerate(rows)
        if isinstance(row, dict) and row.get("basis") == "substrate"
    ]

    parsed_records = []
    for index, envelope in enumerate(records):
        record = _Record(index, envelope)
        _read_payload(record, out, report=bool(substrate_rows) or True)
        if record.readable:
            record.binds = record.payload.get("aeeRunBinding") == binding
            if record.kind in COVERING_KINDS and record.binds:
                _check_kind(record, context, out)
            elif record.kind in COVERING_KINDS:
                record.kind_ok = False
        parsed_records.append(record)

    def resolved(row):
        refs = row.get("observationRefs")
        if not isinstance(refs, list):
            return []
        return [
            parsed_records[ref]
            for ref in refs
            if _is_integer(ref) and 0 <= ref < len(parsed_records)
        ]

    # --- the five per-substrate-row requirements ---------------------------
    for index, row in substrate_rows:
        where = "attackResults[%d]" % index

        # R5. "A producer MUST NOT declare basis: substrate on a row it cannot
        # cover under the coverage validity requirements above: such a row is
        # not merely mislabeled, it makes the attestation invalid." The
        # requirements below are keyed on `method`, and the pinned requirement
        # on `attribution`, so a row carrying a missing or out-of-vocabulary
        # value for either cannot be covered by any of them. On a row that is
        # not `basis: substrate` the same value only drives the recompute's
        # fail-closed arm and leaves the statement valid -- see RESOLUTION.md
        # R1 and R5, which are the two halves of one line.
        uncoverable = [
            member
            for member, allowed in (("method", METHOD_VALUES), ("attribution", ATTRIBUTION_VALUES))
            if row.get(member) not in allowed
        ]
        if uncoverable:
            out.append(
                Finding(
                    "cv-uncoverable-substrate-row",
                    "%s declares basis: substrate carrying a missing or "
                    "out-of-vocabulary %s, so no coverage requirement can cover it"
                    % (where, " and ".join(uncoverable)),
                )
            )

        refs = row.get("observationRefs")
        if not isinstance(refs, list) or not refs:
            out.append(Finding("cv-refs-empty", "%s carries basis: substrate with no observationRefs" % where))
            continue
        covering = resolved(row)
        kinds = {r.kind for r in covering if r.readable}
        clean = is_clean_row(row, labels, caught)
        method = row.get("method")

        if not clean and method == "intercepted" and "interception" not in kinds:
            out.append(Finding("cv-record-class", "caught %s with method intercepted resolves no interception record" % where))
        if method == "reconstructed" and "examination" not in kinds:
            out.append(Finding("cv-record-class", "%s with method reconstructed resolves no examination record" % where))
        if clean and method == "intercepted":
            if "arming" not in kinds:
                out.append(Finding("cv-record-class", "clean %s with method intercepted resolves no arming record" % where))
            arming_digests = [
                r.payload.get("aeePostureDigest") for r in covering if r.kind == "arming" and r.readable
            ]
            if not any(
                r.kind == "sealed" and r.readable and _seal_covers(r, arming_digests, context)
                for r in covering
            ):
                out.append(Finding("cv-record-class", "clean %s with method intercepted resolves no covering sealed record" % where))

        for record in covering:
            if not record.readable:
                out.append(Finding("cv-payload-parse", "%s resolves %s, whose payload does not parse under the profile" % (where, record.where)))
            elif not record.binds:
                out.append(Finding("cv-run-binding", "%s resolves %s, whose aeeRunBinding does not equal the derived run binding" % (where, record.where)))

        # R2. "the weakest aeeMethod across its *covering* records". A
        # moat-drop, an uncommitted-observation and an unrecognised kind all
        # cover nothing, so none of them may weaken a row.
        strengths = [
            _METHOD_STRENGTH[r.method]
            for r in covering
            if r.readable and r.kind in COVERING_KINDS and r.method in _METHOD_STRENGTH
        ]
        if strengths and method in _METHOD_STRENGTH and _METHOD_STRENGTH[method] > min(strengths):
            out.append(Finding("cv-method-strength", "%s declares method %r, stronger than the weakest aeeMethod across the records it resolves" % (where, method)))

    if records:
        try:
            if root_for_records(records) != predicate.get("batchRoot"):
                out.append(Finding("cv-batch-root", "batchRoot does not equal the recompute over the carried records"))
        except (MerkleError, DSSEError) as exc:
            out.append(Finding("cv-batch-root", "batchRoot cannot be recomputed: %s" % exc))

    # --- the six further requirements --------------------------------------
    # A clean row resolves no index to an interception record. Every row.
    for index, row in enumerate(rows):
        if not isinstance(row, dict) or not is_clean_row(row, labels, caught):
            continue
        for record in resolved(row):
            if record.kind == "interception":
                out.append(Finding("cv-clean-row-interception", "clean attackResults[%d] resolves %s, an interception record" % (index, record.where)))

    # Every carried interception record is resolved by at least one caught row.
    caught_refs = set()
    for row in rows:
        if isinstance(row, dict) and not is_clean_row(row, labels, caught):
            caught_refs.update(r.index for r in resolved(row))
    for record in parsed_records:
        if record.kind == "interception" and record.index not in caught_refs:
            out.append(Finding("cv-orphan-interception", "%s is an interception record no caught row resolves" % record.where))

    # A substrate-carrying statement carries a satisfying sealed record.
    if substrate_rows:
        if not any(r.kind == "sealed" and r.binds and r.kind_ok for r in parsed_records):
            out.append(Finding("cv-sealed-existence", "a row carries basis: substrate and no carried sealed record binds to this run and satisfies every constraint of its kind"))

    # aeeObservedSet on every carried sealed record.
    try:
        observed_paes = [
            pae_for_record(r.envelope) for r in parsed_records if r.kind in OBSERVED_KINDS
        ]
        expected_set = observed_set_from_paes(observed_paes)
    except DSSEError:
        expected_set = None
    if expected_set is not None:
        for record in parsed_records:
            if record.kind == "sealed" and record.readable and record.payload.get("aeeObservedSet") != expected_set:
                out.append(Finding("cv-observed-set", "%s aeeObservedSet does not equal the recompute over the carried interception and examination records" % record.where))

    # attribution: pinned.
    for index, row in enumerate(rows):
        if not isinstance(row, dict):
            continue
        attack = row.get("attackId")
        entry = expected_payloads.get(attack)
        where = "attackResults[%d]" % index
        if row.get("attribution") != "pinned":
            continue
        interceptions = [r for r in resolved(row) if r.kind == "interception" and r.readable]
        if not interceptions:
            out.append(Finding("cv-pinned-no-interception", "%s declares attribution: pinned and resolves no interception record" % where))
            continue
        if not isinstance(entry, list) or not entry:
            out.append(Finding("cv-pinned-no-expectation", "%s declares attribution: pinned and its attackId carries no expectedPayloads entry" % where))
            continue
        for record in interceptions:
            commitment = record.payload.get("aeePayloadCommitment")
            if not isinstance(commitment, list) or not set(commitment) & set(entry):
                out.append(Finding("cv-pinned-commitment", "%s resolves %s, whose aeePayloadCommitment carries no value the corpus declared for this attack" % (where, record.where)))

    # aeeAssessedAttacks must cover the assessed classes.
    coverage = predicate.get("coverage")
    if isinstance(coverage, dict) and isinstance(coverage.get("assessedClasses"), list):
        assessed = set()
        for class_code in coverage["assessedClasses"]:
            entry = classes.get(class_code)
            if isinstance(entry, list):
                assessed.update(entry)
        for record in parsed_records:
            if record.kind != "arming" or not record.readable:
                continue
            declared_attacks = record.payload.get("aeeAssessedAttacks")
            if isinstance(declared_attacks, list) and not assessed <= set(declared_attacks):
                out.append(Finding("cv-assessed-subset", "the assessed classes' identifiers are not a subset of %s aeeAssessedAttacks" % record.where))

    # Every identifier a seal names obliges a caught row.
    caught_ids = {
        row.get("attackId")
        for row in rows
        if isinstance(row, dict) and row.get("containmentObserved") in caught
    }
    for record in parsed_records:
        if record.kind != "sealed" or not record.readable:
            continue
        named = record.payload.get("aeeObservedAttacks")
        if isinstance(named, list):
            unmatched = [x for x in named if x not in caught_ids]
            if unmatched:
                out.append(Finding("cv-observed-attacks-row", "%s aeeObservedAttacks names %d identifier(s) with no caught row" % (record.where, len(unmatched))))
    return out
