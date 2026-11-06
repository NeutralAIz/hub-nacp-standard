# NACP Conformance Suite

This directory contains automated tests to verify that an implementation (or a set of examples) conforms to the NACP standard.

## Structure

- `test_schemas.py`: Validates all files in `examples/` against the matching `schemas/*.schema.json`.
- `test_lifecycle.py`: Asserts the §4.2 transition table (every legal transition allowed, a sample of illegal ones rejected).
- `test_envelope.py`: Signed-envelope validation + canonical-JSON byte-identity (re-serialize an example, assert identical bytes).
- `test_envelope_signatures.py`: Real Ed25519 signing and verification, canonical UTF-8/order equivalence, and rejection of tampered or malformed signatures.

## Usage

To run the suite, you need Python 3.9+ and `pytest`, `jsonschema`, and `cryptography` (which provides Ed25519).

```bash
pip install -r requirements-test.txt
pytest conformance/
```

Downstream implementations SHOULD point their CI at a pinned tag of this repo and run this suite against their generated NACP artifacts.
