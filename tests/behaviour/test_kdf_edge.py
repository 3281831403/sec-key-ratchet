"""Five boundary tests for derivation bytes, skip limits and replay."""

import hashlib
import hmac

import pytest

from ratchet.kdf import (
    MAX_SKIP,
    cache_key,
    kdf_chain,
    lookup_key,
    message_key,
    ratchet_batch,
    skip_chain,
)

KEY_A = bytes(range(32))
KEY_B = bytes(range(32, 64))
DOMAIN_A = "alice-to-bob"
DOMAIN_B = "bob-to-alice"

CHAIN_A1 = bytes.fromhex(
    "85651083428dfcd717302d8303cbb8d57edca817eb0693afc8b5765d5abaa195"
)
CHAIN_A2 = bytes.fromhex(
    "199e54ef913c214508efbe19ce3dafdc1ca165e124dffadbee274080512dc614"
)
CHAIN_A64 = bytes.fromhex(
    "cd304c1d38def2b6130c8b4247af21cc05a9e50e52664307c800a05af1a0fb38"
)
MSG_A1 = bytes.fromhex(
    "f7d337e7855c8431c7551b268053b2f2af51fe99f3b5fe450d2d1c2d1f4fce24"
)
MSG_A2 = bytes.fromhex(
    "d8fc0f37eb109416a0a57ba986f124784e2a53281a3c272cc096cad61b08c622"
)
MSG_A64 = bytes.fromhex(
    "9093e71b274742e6e166b9536de78e4f356aea25ef93431f1bf4adb6cf072502"
)
CHAIN_B3 = bytes.fromhex(
    "b37253869bbac6b79c276546015ab23fb46b4bd3e221b8d8b7ca77e6e9dc1d72"
)
MSG_B3 = bytes.fromhex(
    "f3899117230a0ac08bed2422264efb5f2649b6e381e98635510f37167d7b9347"
)
CROSS_CHAIN_B1 = bytes.fromhex(
    "dedc6afb0316ad6c820c0ca4a93efc5867ca0d9323a518e22192942eb66f90b9"
)


def _state(key=KEY_A, domain=DOMAIN_A):
    return {"chain_key": key, "counter": 0, "domain": domain, "cache": {}}


def _seal(key, plaintext, nonce):
    stream = hmac.new(key, b"test-stream" + nonce, hashlib.sha256).digest()
    body = bytes(left ^ right for left, right in zip(plaintext, stream))
    tag = hmac.new(
        key, b"test-tag" + nonce + body, hashlib.sha256
    ).digest()[:16]
    return body + tag


def _open(key, sealed, nonce):
    body = sealed[:-16]
    tag = sealed[-16:]
    expected = hmac.new(
        key, b"test-tag" + nonce + body, hashlib.sha256
    ).digest()[:16]
    if not hmac.compare_digest(tag, expected):
        raise ValueError("bad tag")
    stream = hmac.new(key, b"test-stream" + nonce, hashlib.sha256).digest()
    return bytes(left ^ right for left, right in zip(body, stream))


def test_same_parameters_are_byte_stable():
    first = kdf_chain(KEY_A, 1, DOMAIN_A + "/chain")
    second = kdf_chain(KEY_A, 1, DOMAIN_A + "/chain")

    assert type(first) is bytes
    assert len(first) == 32
    assert first == CHAIN_A1
    assert second == first
    assert message_key(CHAIN_A1, 1) == MSG_A1
    assert message_key(CHAIN_A1, 1) == message_key(CHAIN_A1, 1)


def test_different_domains_produce_different_bytes():
    first = kdf_chain(KEY_A, 1, DOMAIN_A + "/chain")
    second = kdf_chain(KEY_A, 1, DOMAIN_B + "/chain")

    assert first == CHAIN_A1
    assert second == CROSS_CHAIN_B1
    assert first != second


def test_skip_chain_boundary_at_max_skip():
    assert MAX_SKIP == 64
    state = _state()

    within = skip_chain(state, MAX_SKIP)

    assert within["counter"] == MAX_SKIP
    assert within["chain_key"] == CHAIN_A64
    assert within["message_key"] == MSG_A64
    assert [item["counter"] for item in within["skipped"]] == list(
        range(1, MAX_SKIP)
    )
    assert len(within["skipped"]) == MAX_SKIP - 1
    assert all(len(item["key"]) == 32 for item in within["skipped"])
    assert len({item["key"] for item in within["skipped"]}) == MAX_SKIP - 1

    with pytest.raises(ValueError):
        skip_chain(state, MAX_SKIP + 1)


def test_out_of_order_message_decrypts_once():
    jumped = skip_chain(_state(), 3)
    skipped = {item["counter"]: item["key"] for item in jumped["skipped"]}

    assert set(skipped) == {1, 2}

    cached = cache_key(jumped, 2, skipped[2])
    plaintext = b"late-message-2"
    sealed = _seal(skipped[2], plaintext, b"nonce-2")

    recovered = _open(lookup_key(cached, 2), sealed, b"nonce-2")
    assert recovered == plaintext

    with pytest.raises(KeyError):
        lookup_key(cached, 2)


def test_bidirectional_batch_matches_individual_runs():
    policy = {"max_steps": 8}
    event_a = {
        "session": "a2b",
        "state": _state(KEY_A, DOMAIN_A),
        "steps": 2,
    }
    event_b = {
        "session": "b2a",
        "state": _state(KEY_B, DOMAIN_B),
        "steps": 3,
    }

    batch = ratchet_batch([event_a, event_b], policy)
    alone_a = ratchet_batch([event_a], policy)
    alone_b = ratchet_batch([event_b], policy)

    assert batch["a2b"] == alone_a["a2b"]
    assert batch["b2a"] == alone_b["b2a"]
    assert batch["a2b"]["counter"] == 2
    assert batch["a2b"]["chain_key"] == CHAIN_A2
    assert batch["b2a"]["counter"] == 3
    assert batch["b2a"]["chain_key"] == CHAIN_B3
    assert batch["b2a"]["message_key"] == MSG_B3
    assert batch["a2b"]["message_key"] != batch["b2a"]["message_key"]