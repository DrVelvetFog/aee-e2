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
