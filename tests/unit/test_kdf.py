"""Ten contract tests, one for each defect in README order."""

import copy

import pytest

from ratchet.kdf import (
    CACHE_WINDOW,
    MAX_SKIP,
    cache_key,
    kdf_chain,
    lookup_key,
    message_key,
    next_chain,
    ratchet_batch,
    skip_chain,
    verify_chain_link,
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
CHAIN_A3 = bytes.fromhex(
    "a24c0d3f340d45ac38c3843f670316a1f62bf1f12959cc2607b61e94ff1920a3"
)
MSG_A1 = bytes.fromhex(
    "f7d337e7855c8431c7551b268053b2f2af51fe99f3b5fe450d2d1c2d1f4fce24"
)
MSG_A2 = bytes.fromhex(
    "d8fc0f37eb109416a0a57ba986f124784e2a53281a3c272cc096cad61b08c622"
)
MSG_A3 = bytes.fromhex(
    "a07711d93674a0582bbf2eb011a9afb808ad34b22b331a79e7dd28430664feae"
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


def test_kdf_chain_binds_domain():
    assert kdf_chain(KEY_A, 7, "chain") == bytes.fromhex(
        "44358dbebe3409f78eff59a8a8534968189a7f0f9b3aef6db97636c6e15c09f2"
    )
    assert kdf_chain(KEY_A, 7, "message") == bytes.fromhex(
        "6b5d2f114bc1cfc0215ebb8cfdaf479666b75ca549a786ece8e90d84363fab2d"
    )
    assert kdf_chain(KEY_A, 7, "chain") != kdf_chain(KEY_A, 7, "message")


def test_next_chain_is_pure_and_retry_is_stable():
    state = _state()
    before = copy.deepcopy(state)

    advanced = next_chain(state)

    assert advanced["counter"] == 1
    assert advanced["chain_key"] == CHAIN_A1
    assert advanced["message_key"] == MSG_A1
    assert advanced["cache"] is not state["cache"]
    assert state == before
    assert next_chain(state) == advanced


def test_skip_chain_rejects_jump_over_limit():
    assert MAX_SKIP == 64
    state = _state()
    before = copy.deepcopy(state)

    with pytest.raises(ValueError):
        skip_chain(state, MAX_SKIP + 1)

    assert state == before


def test_skip_chain_keeps_skipped_message_keys():
    state = _state()
    before = copy.deepcopy(state)

    jumped = skip_chain(state, 3)

    assert jumped["counter"] == 3
    assert jumped["chain_key"] == CHAIN_A3
    assert jumped["message_key"] == MSG_A3
    assert [(item["counter"], item["key"]) for item in jumped["skipped"]] == [
        (1, MSG_A1),
        (2, MSG_A2),
    ]
    assert state == before


def test_cache_key_evicts_lowest_counter_not_earliest_insert():
    assert CACHE_WINDOW == 8
    state = _state()

    # Counter 30 is inserted first and must survive. Counter 10 is inserted
    # later but is the smallest counter and must be evicted when 17 arrives.
    for counter in (30, 10, 11, 12, 13, 14, 15, 16):
        state = cache_key(state, counter, bytes([counter]) * 32)

    assert sorted(state["cache"]) == [10, 11, 12, 13, 14, 15, 16, 30]

    evicted = cache_key(state, 17, b"\x11" * 32)

    assert sorted(evicted["cache"]) == [11, 12, 13, 14, 15, 16, 17, 30]
    assert 10 not in evicted["cache"]
    assert 30 in evicted["cache"]


def test_lookup_key_removes_cached_key():
    state = cache_key(_state(), 5, KEY_B)

    assert lookup_key(state, 5) == KEY_B
    assert state["cache"] == {}

    with pytest.raises(KeyError):
        lookup_key(state, 5)


def test_verify_chain_link_rejects_cross_domain():
    old = {"chain_key": KEY_A, "counter": 0, "domain": DOMAIN_A}
    valid = {"chain_key": CHAIN_A1, "counter": 1, "domain": DOMAIN_A}
    cross_with_old_key = {
        "chain_key": CHAIN_A1,
        "counter": 1,
        "domain": DOMAIN_B,
    }
    cross_with_new_key = {
        "chain_key": CROSS_CHAIN_B1,
        "counter": 1,
        "domain": DOMAIN_B,
    }

    assert verify_chain_link(old, valid, 1) is True
    assert verify_chain_link(old, cross_with_old_key, 1) is False
    assert verify_chain_link(old, cross_with_new_key, 1) is False


def test_verify_chain_link_rejects_skipped_level():
    old = {"chain_key": KEY_A, "counter": 0, "domain": DOMAIN_A}
    skipped = {"chain_key": CHAIN_A2, "counter": 2, "domain": DOMAIN_A}

    assert verify_chain_link(old, skipped, 2) is False


def test_ratchet_batch_does_not_share_chain():
    state_a = _state(KEY_A, DOMAIN_A)
    state_b = _state(KEY_B, DOMAIN_B)
    before_a = copy.deepcopy(state_a)
    before_b = copy.deepcopy(state_b)
    events = [
        {"session": "a2b", "state": state_a, "steps": 2},
        {"session": "b2a", "state": state_b, "steps": 3},
    ]

    batch = ratchet_batch(events, {"max_steps": 8})

    assert batch["a2b"]["counter"] == 2
    assert batch["a2b"]["chain_key"] == CHAIN_A2
    assert batch["a2b"]["message_key"] == MSG_A2
    assert batch["b2a"]["counter"] == 3
    assert batch["b2a"]["chain_key"] == CHAIN_B3
    assert batch["b2a"]["message_key"] == MSG_B3
    assert batch["a2b"]["chain_key"] != batch["b2a"]["chain_key"]
    assert state_a == before_a
    assert state_b == before_b


def test_message_key_rejects_counter_overflow():
    assert message_key(CHAIN_A1, 1) == MSG_A1

    with pytest.raises(ValueError):
        message_key(CHAIN_A1, 2**32)

    with pytest.raises(ValueError):
        message_key(CHAIN_A1, -1)