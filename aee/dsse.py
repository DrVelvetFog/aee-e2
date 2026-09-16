"""DSSE envelopes: Pre-Authentication Encoding, and the bytes it runs over.

Spec basis (head 25ac8581): each observation record is a DSSE-shaped envelope
carrying ``payload`` (base64 of the exact canonical bytes the substrate signed),
``payloadType``, and ``signatures``; a consumer verifies each record's
signature, "DSSE PAE over ``(payloadType, payload)``", before relying on any
field inside the payload.

DSSE defines PAE over the *serialised body*, which the envelope carries
base64-encoded. ``pae_for_record`` therefore decodes ``payload`` first. The
spec pins DSSE normatively, so this is a reading of a referenced document
rather than a choice, but it is the one place the wording alone could be read
either way and it is recorded as such.
"""

import base64
import binascii

__all__ = ["pae", "decode_payload", "pae_for_record", "DSSEError"]


class DSSEError(ValueError):
    """An envelope that cannot be reduced to pre-authentication bytes."""


def pae(payload_type, body):
    """DSSE Pre-Authentication Encoding.

    ``DSSEv1 SP len(type) SP type SP len(body) SP body``, where each length is
    the ASCII decimal count of *bytes* and SP is a single 0x20.
    """
    if isinstance(payload_type, str):
        payload_type = payload_type.encode("utf-8")
    if not isinstance(payload_type, (bytes, bytearray)):
        raise DSSEError("payloadType must be text or bytes")
    if not isinstance(body, (bytes, bytearray)):
        raise DSSEError("body must be bytes; decode the base64 payload first")
    return b"DSSEv1 %d %s %d %s" % (
        len(payload_type),
        bytes(payload_type),
        len(body),
        bytes(body),
    )


def decode_payload(payload):
    """Decode an envelope's base64 ``payload`` member to the signed bytes.

    Standard base64 with padding, rejected on any character outside the
    alphabet. A lenient decode would let two rails derive different bodies from
    the same envelope, which is the divergence the canonical form exists to
    prevent.
    """
    if not isinstance(payload, str):
        raise DSSEError("payload must be a JSON string")
    try:
        return base64.b64decode(payload, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise DSSEError("payload is not valid base64: %s" % exc) from exc


def pae_for_record(record):
    """Pre-authentication bytes for one observation record."""
    if not isinstance(record, dict):
        raise DSSEError("observation record must be a JSON object")
    for member in ("payload", "payloadType"):
        if member not in record:
            raise DSSEError("observation record is missing %r" % member)
    payload_type = record["payloadType"]
    if not isinstance(payload_type, str):
        raise DSSEError("payloadType must be a JSON string")
    return pae(payload_type, decode_payload(record["payload"]))
