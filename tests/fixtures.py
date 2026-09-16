"""Statement fixtures built from the spec's own example shape.

Digests are computed rather than written down, so a fixture is always
self-consistent and a test that wants an inconsistency has to introduce one
deliberately.
"""

import base64
import copy

from aee.bindings import corpus_digest, vocabulary_digest
from aee.jcs import canonicalize

HEX = "%064d"

LABELS = ["egress_captured", "no_egress"]
CAUGHT = ["egress_captured"]


def manifest(classes=None, expected_payloads=None):
    # `classes if classes is not None`, not `classes or` -- an empty classes
    # object is a case the manifest floor exists to catch, so it must survive
    # the default rather than being replaced by it.
    out = {"classes": {"CO": ["CO-EXFIL-1"]} if classes is None else classes}
    if expected_payloads is not None:
        out["expectedPayloads"] = expected_payloads
    return out


def environment(manifest_obj=None, labels=None, caught=None, posture="sinkhole",
                run_entropy=True):
    manifest_obj = manifest_obj if manifest_obj is not None else manifest()
    labels = list(LABELS if labels is None else labels)
    caught = list(CAUGHT if caught is None else caught)
    env = {
        "substrate": {"name": "substrate", "digest": {"sha256": HEX % 1}},
        "corpus": {
            "name": "corpus",
            "uri": "pkg:example/corpus@1",
            "digest": {"sha256": corpus_digest(manifest_obj)},
            "manifest": manifest_obj,
        },
        "catchPolicy": {"digest": {"sha256": HEX % 3}},
        "networkPosture": {"posture": posture, "digest": {"sha256": HEX % 4}},
        "observationVocabulary": {
            "digest": {"sha256": vocabulary_digest(labels, caught)},
            "labels": labels,
            "caught": caught,
        },
    }
    if run_entropy:
        env["runEntropy"] = {"digest": {"sha256": HEX % 6}}
    return env


def row(attack_id="CO-EXFIL-1", observed="no_egress", basis="artifact",
        method="intercepted", attribution="paired", actual_layer=None, **extra):
    if actual_layer is None:
        actual_layer = "none" if observed not in CAUGHT else "policy.egress_sinkhole"
    out = {
        "attackId": attack_id,
        "containmentObserved": observed,
        "basis": basis,
        "method": method,
        "attribution": attribution,
        "actualLayer": actual_layer,
    }
    out.update(extra)
    return out


def record(body=None, payload_type="application/vnd.example+json"):
    body = body if body is not None else {"aeeKind": "interception"}
    return {
        "payload": base64.b64encode(canonicalize(body)).decode("ascii"),
        "payloadType": payload_type,
        "signatures": [{"keyid": "00", "sig": "AA=="}],
    }


def statement(rows=None, result="pass_indirect", env=None, coverage=None,
              records=None, batch_root=None, issued_at="2026-06-23T16:08:07Z",
              **predicate_extra):
    rows = [row()] if rows is None else rows
    predicate = {
        "result": result,
        "observationEnvironment": env if env is not None else environment(),
        "coverage": coverage
        if coverage is not None
        else {"assessedClasses": ["CO"], "outOfScope": {}, "routedElsewhere": {}},
        "attackResults": list(rows),
        "issuedAt": issued_at,
    }
    if records is not None:
        predicate["observationRecords"] = records
    if batch_root is not None:
        predicate["batchRoot"] = batch_root
    predicate.update(predicate_extra)
    return {
        "_type": "https://in-toto.io/Statement/v1",
        "subject": [{"name": "artifact", "digest": {"sha256": HEX % 7}}],
        "predicateType": (
            "https://in-toto.io/attestation/adversarial-execution-evidence/v0.7"
        ),
        "predicate": predicate,
    }


def mutate(base, path, value):
    """Copy ``base`` with one nested member replaced. ``path`` is a tuple."""
    out = copy.deepcopy(base)
    node = out
    for step in path[:-1]:
        node = node[step]
    node[path[-1]] = value
    return out


def drop(base, path):
    """Copy ``base`` with one nested member removed."""
    out = copy.deepcopy(base)
    node = out
    for step in path[:-1]:
        node = node[step]
    del node[path[-1]]
    return out


# --- a fully consistent substrate statement ---------------------------------

COMMITMENT = "aa" * 32


def _payload_record(body):
    return {
        "payload": base64.b64encode(canonicalize(body)).decode("ascii"),
        "payloadType": "application/vnd.example.observation+json",
        "signatures": [{"keyid": "00", "sig": "AA=="}],
    }


def substrate_statement(seal_posture_digest=None, still_armed=True, drop_count=0,
                        drop_bound=None, observed_attacks=None,
                        assessed_attacks=None, armed_at="2026-06-23T15:00:00Z",
                        extra_records=(), issued_at="2026-06-23T16:08:07Z"):
    """A statement that satisfies every coverage-validity requirement.

    Built in dependency order: environment, then the run binding it implies,
    then the records carrying that binding, then the seal's commitment over
    those records, then the batch root over all of them.
    """
    from aee.bindings import run_binding_digest
    from aee.dsse import pae_for_record
    from aee.merkle import root_for_records
    from aee.observed_set import observed_set_from_paes

    manifest_obj = manifest(
        classes={"CO": ["CO-EXFIL-1", "CO-EXFIL-2"]},
        expected_payloads={"CO-EXFIL-1": [COMMITMENT]},
    )
    env = environment(manifest_obj=manifest_obj)
    subject = [{"name": "artifact", "digest": {"sha256": HEX % 7}}]
    binding = run_binding_digest({"observationEnvironment": env}, subject)
    posture_digest = env["networkPosture"]["digest"]["sha256"]

    interception = _payload_record(
        {
            "aeeRunBinding": binding,
            "aeeKind": "interception",
            "aeeMethod": "intercepted",
            "aeePayloadCommitment": [COMMITMENT],
        }
    )
    arming = _payload_record(
        {
            "aeeRunBinding": binding,
            "aeeKind": "arming",
            "aeeMethod": "intercepted",
            "armedAt": armed_at,
            "aeePostureDigest": posture_digest,
            "aeeAssessedAttacks": list(
                assessed_attacks
                if assessed_attacks is not None
                else ["CO-EXFIL-1", "CO-EXFIL-2"]
            ),
        }
    )
    records = [interception, arming] + list(extra_records)

    observed = observed_set_from_paes(
        pae_for_record(r)
        for r in records
        if json_kind(r) in ("interception", "examination")
    )
    seal_body = {
        "aeeRunBinding": binding,
        "aeeKind": "sealed",
        "aeeMethod": "intercepted",
        "aeeStillArmed": still_armed,
        "aeeDropCount": drop_count,
        "aeePostureDigest": (
            posture_digest if seal_posture_digest is None else seal_posture_digest
        ),
        "aeeObservedSet": observed,
        "aeeObservedAttacks": list(
            observed_attacks if observed_attacks is not None else ["CO-EXFIL-1"]
        ),
    }
    if drop_bound is not None:
        seal_body["aeeDropBound"] = drop_bound
    records = records + [_payload_record(seal_body)]

    rows = [
        row(
            attack_id="CO-EXFIL-1",
            observed="egress_captured",
            basis="substrate",
            method="intercepted",
            attribution="pinned",
            actual_layer="policy.egress_sinkhole",
            observationRefs=[0],
        ),
        row(
            attack_id="CO-EXFIL-2",
            observed="no_egress",
            basis="substrate",
            method="intercepted",
            attribution="paired",
            observationRefs=[1, len(records) - 1],
        ),
    ]
    return {
        "_type": "https://in-toto.io/Statement/v1",
        "subject": subject,
        "predicateType": (
            "https://in-toto.io/attestation/adversarial-execution-evidence/v0.7"
        ),
        "predicate": {
            "result": "fail",
            "observationEnvironment": env,
            "coverage": {
                "assessedClasses": ["CO"],
                "outOfScope": {},
                "routedElsewhere": {},
            },
            "attackResults": rows,
            "observationRecords": records,
            "batchRoot": root_for_records(records),
            "issuedAt": issued_at,
        },
    }


def json_kind(record):
    """The aeeKind inside a record built by this module."""
    import json

    return json.loads(base64.b64decode(record["payload"]))["aeeKind"]


def repayload(record, **changes):
    """Copy a record with its decoded payload updated and re-canonicalised."""
    import json

    body = json.loads(base64.b64decode(record["payload"]))
    for key, value in changes.items():
        if value is _REMOVE:
            body.pop(key, None)
        else:
            body[key] = value
    out = dict(record)
    out["payload"] = base64.b64encode(canonicalize(body)).decode("ascii")
    return out


class _Remove:
    pass


_REMOVE = _Remove()
REMOVE = _REMOVE


def clean_substrate_statement(issued_at="2026-06-23T16:08:07Z"):
    """A statement whose only row is a clean intercepted substrate row.

    This is the shape that reaches `result: pass`, and the only one that does:
    a live substrate vantage was armed and no capture was attributed to it.
    It carries an arming and a sealed record and no interception record at all,
    so the seal's aeeObservedSet commits to the empty array -- the case NOTES.md
    entry 5 records a reading for.
    """
    from aee.bindings import run_binding_digest
    from aee.merkle import root_for_records
    from aee.observed_set import observed_set_from_paes

    manifest_obj = manifest(classes={"CO": ["CO-EXFIL-1"]})
    env = environment(manifest_obj=manifest_obj)
    subject = [{"name": "artifact", "digest": {"sha256": HEX % 7}}]
    binding = run_binding_digest({"observationEnvironment": env}, subject)
    posture_digest = env["networkPosture"]["digest"]["sha256"]

    arming = _payload_record(
        {
            "aeeRunBinding": binding,
            "aeeKind": "arming",
            "aeeMethod": "intercepted",
            "armedAt": "2026-06-23T15:00:00Z",
            "aeePostureDigest": posture_digest,
            "aeeAssessedAttacks": ["CO-EXFIL-1"],
        }
    )
    seal = _payload_record(
        {
            "aeeRunBinding": binding,
            "aeeKind": "sealed",
            "aeeMethod": "intercepted",
            "aeeStillArmed": True,
            "aeeDropCount": 0,
            "aeePostureDigest": posture_digest,
            "aeeObservedSet": observed_set_from_paes([]),
            "aeeObservedAttacks": [],
        }
    )
    records = [arming, seal]
    return {
        "_type": "https://in-toto.io/Statement/v1",
        "subject": subject,
        "predicateType": (
            "https://in-toto.io/attestation/adversarial-execution-evidence/v0.7"
        ),
        "predicate": {
            "result": "pass",
            "observationEnvironment": env,
            "coverage": {
                "assessedClasses": ["CO"],
                "outOfScope": {},
                "routedElsewhere": {},
            },
            "attackResults": [
                row(
                    attack_id="CO-EXFIL-1",
                    observed="no_egress",
                    basis="substrate",
                    method="intercepted",
                    attribution="paired",
                    observationRefs=[0, 1],
                )
            ],
            "observationRecords": records,
            "batchRoot": root_for_records(records),
            "issuedAt": issued_at,
        },
    }
