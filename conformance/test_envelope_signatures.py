"""Q-2866 rank 3 finding; NACP_SPECIFICATION.md sections 8.1 and 8.1.2.

Exercise the signed-envelope reference binding with the real Ed25519 library.
Keys are generated solely for each test and never stored or logged.
"""
import base64
from copy import deepcopy

import ed25519
import pytest

import test_envelope as binding


@pytest.fixture
def envelope():
    return {
        "version": "1.1",
        "msg_id": "73b40563-a1ea-42b5-8627-73804a90ec2c",
        "timestamp": "2026-04-24T12:00:00.000000Z",
        "type": "TASK_ASSIGN",
        "from": "sender",
        "to": "recipient",
        "priority": 5,
        "ttl": 300,
        "payload": {"contract_id": "contract-1", "text": "café 🌍"},
    }


def test_signed_envelope_verifies_with_independent_ed25519(envelope):
    signing_key, verifying_key = ed25519.create_keypair()
    original = deepcopy(envelope)
    signed = binding.sign_envelope(envelope, signing_key)
    assert envelope == original
    assert {k: v for k, v in signed.items() if k != "signature"} == original
    signature = base64.b64decode(signed["signature"], validate=True)
    # Independent consumer of the spec's canonical bytes; no mock verifier.
    verifying_key.verify(signature, binding.canonical_json(signed).encode("utf-8"))
    assert binding.verify_envelope(signed, verifying_key) is True
    # Insertion order is irrelevant, including the nested payload.
    reordered = dict(reversed(list(signed.items())))
    reordered["payload"] = dict(reversed(list(signed["payload"].items())))
    assert binding.verify_envelope(reordered, verifying_key) is True


@pytest.mark.parametrize("target", ["payload", "to", "signature", "wrong_key"])
def test_signed_envelope_rejects_tampering(envelope, target):
    signing_key, verifying_key = ed25519.create_keypair()
    signed = binding.sign_envelope(envelope, signing_key)
    assert binding.verify_envelope(signed, verifying_key) is True
    altered = deepcopy(signed)
    if target == "payload":
        altered["payload"]["text"] += " changed"
    elif target == "to":
        altered["to"] = "attacker"
    elif target == "signature":
        raw = bytearray(base64.b64decode(altered["signature"], validate=True))
        raw[0] ^= 1
        altered["signature"] = base64.b64encode(raw).decode("ascii")
    else:
        _, verifying_key = ed25519.create_keypair()
    assert binding.verify_envelope(altered, verifying_key) is False


@pytest.mark.parametrize("signature", [None, "", "not base64!", "AA=="])
def test_signed_envelope_rejects_missing_or_malformed_signature(envelope, signature):
    _, verifying_key = ed25519.create_keypair()
    if signature is not None:
        envelope["signature"] = signature
    assert binding.verify_envelope(envelope, verifying_key) is False
