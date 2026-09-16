"""Digest bindings: the values a verifier re-derives from carried bytes.

Spec basis (head 25ac8581).

``observationEnvironment`` pins its context by digest. Three of those digests
have their pre-image on the statement's own JSON surface and are therefore
re-derivable offline; three do not, and are pinned out of band by the consumer:

=========================  ==========================================  ==========
digest                     pre-image                                   re-derivable
=========================  ==========================================  ==========
``corpus.digest``          the carried ``manifest`` object              yes
``observationVocabulary``  ``{"caught": [...], "labels": [...]}``       yes
run binding                the eight-member object under Prerequisites  yes
``catchPolicy.digest``     the parsed catch-policy document             no
``runEntropy.digest``      the substrate's run-start checkpoint         no
``substrate.digest``       the substrate's own attestation subject      no
=========================  ==========================================  ==========

"The manifest pre-image travels in the attestation, so a verifier re-derives
``corpus.digest`` offline and any edit to the assessed set (a dropped attack, a
renamed class) fails that check."

The typing discipline the spec states is the reason this split exists at all:
a pre-image "stays on the statement's own JSON surface", never inside a base64
member, because "material inside a base64 member is outside all four" byte-level
rules and "carrying a digest pre-image there would open a second
canonicalization boundary inside a signed statement".

Run binding, quoted in full because the member order and the literal
``aeeBindingVersion`` matter and canonicalisation does not forgive a typo:

> the run binding digest is the lowercase 64-hex SHA-256 of the RFC 8785
> canonicalization of the object ``{"aeeBindingVersion": "2", "catchPolicy":
> "<catchPolicy.digest.sha256>", "corpus": "<corpus.digest.sha256>",
> "networkPosture": "<the lowercase 64-hex SHA-256 of the RFC 8785
> canonicalization of the carried networkPosture object>",
> "observationVocabulary": "<observationVocabulary.digest.sha256>",
> "runEntropy": "<runEntropy.digest.sha256>", "subject":
> "<subject[0].digest.sha256>", "substrate": "<substrate.digest.sha256>"}``

Note that the ``networkPosture`` input is not ``networkPosture.digest.sha256``.
It is a digest over the whole carried ``networkPosture`` object, which contains
that member, so the configuration digest is bound along with the posture token
rather than in place of it.
"""

import hashlib

from .jcs import canonicalize

__all__ = [
    "BINDING_VERSION",
    "POSTURE_VALUES",
    "BindingError",
    "corpus_digest",
    "network_posture_digest",
    "run_binding_digest",
    "sha256_jcs",
    "vocabulary_digest",
]

#: The literal the binding object carries. A string, not a number.
BINDING_VERSION = "2"

#: "The networkPosture.posture vocabulary is closed. Four values are registered".
POSTURE_VALUES = frozenset(
    {"allowlist", "no_network", "sinkhole", "unsafe_bypass_egress"}
)


class BindingError(ValueError):
    """A binding whose inputs are not all present on the statement."""


def sha256_jcs(value):
    """Lowercase 64-hex SHA-256 over the RFC 8785 canonicalisation of ``value``."""
    return hashlib.sha256(canonicalize(value)).hexdigest()


def corpus_digest(manifest):
    """Re-derive ``corpus.digest.sha256`` from the carried manifest."""
    return sha256_jcs(manifest)


def vocabulary_digest(labels, caught):
    """Re-derive ``observationVocabulary.digest.sha256``.

    The pre-image is "the object ``{"caught": [...], "labels": [...]}``" -- the
    two arrays alone, not the carried member with its own ``digest`` inside.
    Canonicalisation sorts the two names, so the order written here is
    presentational only.
    """
    return sha256_jcs({"caught": list(caught), "labels": list(labels)})


def network_posture_digest(network_posture):
    """Digest over the whole carried ``networkPosture`` object.

    This is the run-binding input, not the member ``networkPosture.digest``.
    """
    return sha256_jcs(network_posture)


def _pinned(container, path):
    """Read a ``digest.sha256`` from a descriptor-shaped member."""
    node = container
    for step in path:
        if not isinstance(node, dict) or step not in node:
            raise BindingError("run binding input %r is absent" % ".".join(path))
        node = node[step]
    if not isinstance(node, str):
        raise BindingError("run binding input %r is not a string" % ".".join(path))
    return node


def run_binding_digest(predicate, subject):
    """Re-derive the run binding digest.

    ``subject`` is the statement's ``subject`` array; the binding reads
    ``subject[0].digest.sha256``. The predicate supplies the rest. Every input
    "is a property of the run's configuration and is fixed before corpus
    injection", so nothing here may read a row, a record or an outcome.
    """
    if not isinstance(subject, list) or not subject:
        raise BindingError("run binding input 'subject[0]' is absent")
    environment = predicate.get("observationEnvironment") if isinstance(predicate, dict) else None
    if not isinstance(environment, dict):
        raise BindingError("run binding input 'observationEnvironment' is absent")

    posture = environment.get("networkPosture")
    if not isinstance(posture, dict):
        raise BindingError("run binding input 'networkPosture' is absent")

    binding = {
        "aeeBindingVersion": BINDING_VERSION,
        "catchPolicy": _pinned(environment, ("catchPolicy", "digest", "sha256")),
        "corpus": _pinned(environment, ("corpus", "digest", "sha256")),
        "networkPosture": network_posture_digest(posture),
        "observationVocabulary": _pinned(
            environment, ("observationVocabulary", "digest", "sha256")
        ),
        "runEntropy": _pinned(environment, ("runEntropy", "digest", "sha256")),
        "subject": _pinned(subject[0], ("digest", "sha256")),
        "substrate": _pinned(environment, ("substrate", "digest", "sha256")),
    }
    return sha256_jcs(binding)
