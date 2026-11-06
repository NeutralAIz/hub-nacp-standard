"""Q-2866 rank 3 finding; NACP_SPECIFICATION.md sections 8.1 and 8.1.2.

Exercise the signed-envelope reference binding with the real Ed25519 library.
Keys are generated solely for each test and never stored or logged.
"""
import base64
from copy import deepcopy

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
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
    signing_key = Ed25519PrivateKey.generate()
    verifying_key = signing_key.public_key()
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
    signing_key = Ed25519PrivateKey.generate()
    verifying_key = signing_key.public_key()
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
        verifying_key = Ed25519PrivateKey.generate().public_key()
    assert binding.verify_envelope(altered, verifying_key) is False


@pytest.mark.parametrize("signature", [None, "", "not base64!", "AA=="])
def test_signed_envelope_rejects_missing_or_malformed_signature(envelope, signature):
    verifying_key = Ed25519PrivateKey.generate().public_key()
    if signature is not None:
        envelope["signature"] = signature
    assert binding.verify_envelope(envelope, verifying_key) is False


def test_fixed_non_ascii_signature_vector():
    # Source: NACP_SPECIFICATION.md §8.1.2 and Q-2866 review r14 F1.
    # Public fixture seed, not an operational key. Expected signature was generated
    # directly over the literal bytes below, without canonical_json/sign_envelope.
    signing_key = Ed25519PrivateKey.from_private_bytes(bytes(range(32)))
    verifying_key = signing_key.public_key()
    envelope = {"version": "1.1", "payload": {"text": "café 🌍"}}
    expected_bytes = b'{"payload":{"text":"caf\xc3\xa9 \xf0\x9f\x8c\x8d"},"version":"1.1"}'
    expected_signature = bytes.fromhex(
        "fb8e2eb0e92e876ff3ef7dbb99757298023a49f21002ecbcd351913ce8b240792"
        "d77ce76f3b24d20a9da126407393b7985aa2bea91e3b693f3f640e4548c1209"
    )
    vector = {**envelope, "signature": base64.b64encode(expected_signature).decode("ascii")}
    assert binding.canonical_json(vector).encode("utf-8") == expected_bytes
    verifying_key.verify(expected_signature, expected_bytes)
    assert binding.verify_envelope(vector, verifying_key) is True
    signed = binding.sign_envelope(envelope, signing_key)
    assert base64.b64decode(signed["signature"], validate=True) == expected_signature
    verifying_key.verify(base64.b64decode(signed["signature"], validate=True), expected_bytes)
