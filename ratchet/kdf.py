"""Contracts for a bidirectional end-to-end session key ratchet.

State shape
-----------
A ratchet state is a mapping with these keys:

    chain_key: 32-byte bytes for the chain key at the current counter
    counter: int current chain counter, starting at 0
    domain: non-empty str naming the session and direction
    cache: dict mapping int message counter to 32-byte message key

Counter 0 is the initial chain key. Advancing from counter n - 1 to n derives
the chain key at n from the chain key at n - 1 with:

    kdf_chain(chain_key_at_n_minus_1, n, domain + "/chain")

The message key for counter n is:

    message_key(chain_key_at_n, n)

Wire format
-----------
All digests are HMAC-SHA256 and all keys are 32 bytes. The exact HMAC input for
kdf_chain is:

    b"GSB-RATCHET-v1"
    + len(domain encoded as UTF-8).to_bytes(2, "big")
    + domain encoded as UTF-8
    + counter.to_bytes(8, "big")

The 2-byte domain length is part of the domain separation and prevents two
different domain strings from colliding after concatenation.

The exact HMAC input for message_key is:

    b"GSB-RATCHET-v1/message" + counter.to_bytes(4, "big")

Counters must be integers and must not be silently truncated. Chain KDF
counters are in 0..2**64 - 1. Message counters are in 0..2**32 - 1. An
out-of-range counter raises ValueError.

All functions are deterministic. They use no randomness, clocks, environment
variables, network access or process-global mutable state. The single
intentional state mutation is lookup_key consuming a cached key.
"""

import hashlib
import hmac

PREFIX = b"GSB-RATCHET-v1"
MAX_SKIP = 64
CACHE_WINDOW = 8

_MESSAGE_PREFIX = PREFIX + b"/message"


def _check_key(key) -> None:
    if not isinstance(key, bytes) or len(key) != 32:
        raise ValueError("key must be 32 bytes")


def _check_domain(domain) -> None:
    if not isinstance(domain, str) or not domain:
        raise ValueError("domain must be a non-empty str")


def _check_counter(counter, bits: int) -> None:
    if not isinstance(counter, int) or isinstance(counter, bool):
        raise ValueError("counter must be an int")
    if counter < 0 or counter > 2**bits - 1:
        raise ValueError("counter out of range")


def _check_state(state) -> None:
    if not isinstance(state, dict):
        raise ValueError("state must be a mapping")
    _check_key(state.get("chain_key"))
    _check_domain(state.get("domain"))
    counter = state.get("counter")
    if not isinstance(counter, int) or isinstance(counter, bool) or counter < 0:
        raise ValueError("state counter must be a non-negative int")
    if not isinstance(state.get("cache"), dict):
        raise ValueError("state cache must be a dict")


def kdf_chain(key: bytes, counter: int, domain: str) -> bytes:
    """Derive one 32-byte chain key with explicit domain separation.

    key must be a 32-byte bytes object and domain must be a non-empty str.
    counter must be an int in 0..2**64 - 1. The HMAC-SHA256 input is exactly
    PREFIX, then the UTF-8 domain length as two big-endian bytes, then the
    UTF-8 domain, then the counter as eight big-endian bytes.

    The domain must actually participate in the derivation. Two different
    domains at the same counter, or the same counter used for chain derivation
    and message derivation, must not produce the same key bytes.

    The result is always 32 bytes. Invalid arguments raise ValueError. The same
    arguments always return exactly the same bytes.
    """
    _check_key(key)
    _check_domain(domain)
    _check_counter(counter, 64)
    encoded = domain.encode("utf-8")
    msg = (
        PREFIX
        + len(encoded).to_bytes(2, "big")
        + encoded
        + counter.to_bytes(8, "big")
    )
    return hmac.new(key, msg, hashlib.sha256).digest()


def next_chain(state: dict) -> dict:
    """Advance the chain by exactly one counter without mutating state.

    The new counter is state["counter"] + 1. The new chain key is:

        kdf_chain(state["chain_key"], new_counter, state["domain"] + "/chain")

    and the new message key is:

        message_key(new_chain_key, new_counter)

    Return a fresh mapping that keeps the input fields, copies the cache
    mapping, replaces chain_key and counter, and adds message_key. The input
    state, including its nested cache, must not be modified. Calling this
    function twice from the same input must return equal mappings, so a retry
    after a failed operation starts from the original chain rather than a
    partially advanced one.
    """
    _check_state(state)
    new_counter = state["counter"] + 1
    new_chain_key = kdf_chain(
        state["chain_key"], new_counter, state["domain"] + "/chain"
    )
    new_state = dict(state)
    new_state["cache"] = dict(state["cache"])
    new_state["chain_key"] = new_chain_key
    new_state["counter"] = new_counter
    new_state["message_key"] = message_key(new_chain_key, new_counter)
    return new_state


def skip_chain(state: dict, until: int) -> dict:
    """Advance to until while retaining every skipped message key.

    until must be an int with state["counter"] < until. The number of steps is
    until - state["counter"]. If that number is greater than MAX_SKIP, raise
    ValueError before deriving anything. Exactly MAX_SKIP steps are allowed.

    Starting from the chain key at the old counter, derive the chain key at
    every counter c in old_counter + 1 .. until with:

        kdf_chain(previous_chain_key, c, state["domain"] + "/chain")

    Derive the corresponding message key with message_key(chain_at_c, c).

    Return a fresh mapping that keeps the input fields, copies the cache,
    sets chain_key to the key at until, sets counter to until, sets message_key
    to the message key at until, and sets skipped to a list ordered by counter:

        [{"counter": c, "key": message_key_at_c}, ...]

    for every c strictly between the old counter and until. The input state
    must not be modified. Skipped keys must be retained so an out-of-order
    message can still be decrypted later. Invalid until, an over-limit jump or
    a malformed state raises ValueError.
    """
    _check_state(state)
    if not isinstance(until, int) or isinstance(until, bool):
        raise ValueError("until must be an int")
    old_counter = state["counter"]
    if until <= old_counter:
        raise ValueError("until must be greater than the current counter")
    steps = until - old_counter
    if steps > MAX_SKIP:
        raise ValueError("jump exceeds MAX_SKIP")

    domain = state["domain"] + "/chain"
    chain_key = state["chain_key"]
    skipped = []
    for c in range(old_counter + 1, until + 1):
        chain_key = kdf_chain(chain_key, c, domain)
        mk = message_key(chain_key, c)
        if c < until:
            skipped.append({"counter": c, "key": mk})

    new_state = dict(state)
    new_state["cache"] = dict(state["cache"])
    new_state["chain_key"] = chain_key
    new_state["counter"] = until
    new_state["message_key"] = mk
    new_state["skipped"] = skipped
    return new_state


def message_key(chain_key: bytes, counter: int) -> bytes:
    """Derive the 32-byte message key for one counter.

    chain_key must be a 32-byte bytes object. counter must be an int in
    0..2**32 - 1. The HMAC-SHA256 input is exactly the fixed message purpose
    prefix followed by counter as four big-endian bytes.

    A counter outside the four-byte range raises ValueError. The counter must
    never be masked, wrapped or truncated. The same chain key and counter always
    return exactly the same bytes.
    """
    _check_key(chain_key)
    _check_counter(counter, 32)
    msg = _MESSAGE_PREFIX + counter.to_bytes(4, "big")
    return hmac.new(chain_key, msg, hashlib.sha256).digest()


def cache_key(state: dict, counter: int, key: bytes) -> dict:
    """Insert one out-of-order message key into the cache.

    Return a fresh mapping whose cache is a fresh dict with counter mapped to
    key. If counter is already present, replace its value. The cache holds at
    most CACHE_WINDOW entries. While it is over the window, remove the entry
    with the smallest counter, not the entry inserted first. This is a counter
    window: a high counter that arrived early must not be evicted merely because
    it is the oldest insertion.

    The input state and its cache must not be modified. counter must be a
    non-negative int and key must be 32 bytes; invalid input raises ValueError.
    """
    _check_state(state)
    if not isinstance(counter, int) or isinstance(counter, bool) or counter < 0:
        raise ValueError("counter must be a non-negative int")
    _check_key(key)
    new_cache = dict(state["cache"])
    new_cache[counter] = key
    while len(new_cache) > CACHE_WINDOW:
        del new_cache[min(new_cache)]
    new_state = dict(state)
    new_state["cache"] = new_cache
    return new_state


def lookup_key(state: dict, counter: int) -> bytes:
    """Pop and return a cached message key, making the key one-shot.

    The key must be removed from state["cache"] before it is returned. A second
    lookup for the same counter raises KeyError, so a captured ciphertext cannot
    be decrypted twice with the same cached key. This function intentionally
    mutates only state["cache"]; the other state fields are left unchanged.
    A missing counter raises KeyError. Malformed input raises ValueError.
    """
    _check_state(state)
    if not isinstance(counter, int) or isinstance(counter, bool) or counter < 0:
        raise ValueError("counter must be a non-negative int")
    return state["cache"].pop(counter)


def verify_chain_link(old: dict, new: dict, counter: int) -> bool:
    """Return whether new is the exact one-step successor of old at counter.

    Return True only when all of these hold:

    old and new have non-empty bytes chain_key and non-empty str domain;
    the two domains are equal;
    old["counter"] is counter - 1 and new["counter"] is counter;
    new["chain_key"] equals
    kdf_chain(old["chain_key"], counter, old["domain"] + "/chain").

    A different domain is false even when the supplied key bytes were derived
    under that other domain. A skipped level is false: old counter 0 and new
    counter 2 cannot validate for counter 2. Malformed input returns False
    instead of raising. The function does not modify either mapping.
    """
    try:
        if not isinstance(old, dict) or not isinstance(new, dict):
            return False
        old_key = old["chain_key"]
        new_key = new["chain_key"]
        old_domain = old["domain"]
        new_domain = new["domain"]
        if not isinstance(old_key, bytes) or not old_key:
            return False
        if not isinstance(new_key, bytes) or not new_key:
            return False
        if not isinstance(old_domain, str) or not old_domain:
            return False
        if not isinstance(new_domain, str) or not new_domain:
            return False
        if old_domain != new_domain:
            return False
        if old["counter"] != counter - 1 or new["counter"] != counter:
            return False
        expected = kdf_chain(old_key, counter, old_domain + "/chain")
        return hmac.compare_digest(new_key, expected)
    except (KeyError, TypeError, ValueError):
        return False


def ratchet_batch(events: list, policy: dict) -> dict:
    """Advance several sessions independently and return their final states.

    events is a sequence of mappings with:

        session: unique session id
        state: initial ratchet state
        steps: non-negative int number of next_chain applications

    policy is a mapping with a positive int max_steps. Each event is checked
    against the policy. A missing field, negative steps, steps above max_steps
    or a duplicate session raises ValueError.

    Every event must start from its own state. The chain key, counter, message
    key and cache of one event must never be reused by another event, even when
    the events are processed in one call. Return exactly a new dict mapping
    session to the final state produced by applying next_chain steps times.
    Input states are not modified. Empty events returns an empty dict.
    """
    if not isinstance(policy, dict):
        raise ValueError("policy must be a mapping")
    max_steps = policy.get("max_steps")
    if (
        not isinstance(max_steps, int)
        or isinstance(max_steps, bool)
        or max_steps <= 0
    ):
        raise ValueError("policy max_steps must be a positive int")
    if not isinstance(events, (list, tuple)):
        raise ValueError("events must be a sequence")

    result = {}
    for event in events:
        if not isinstance(event, dict):
            raise ValueError("event must be a mapping")
        if "session" not in event or "state" not in event or "steps" not in event:
            raise ValueError("event missing a required field")
        session = event["session"]
        state = event["state"]
        steps = event["steps"]
        if session in result:
            raise ValueError("duplicate session")
        if (
            not isinstance(steps, int)
            or isinstance(steps, bool)
            or steps < 0
        ):
            raise ValueError("steps must be a non-negative int")
        if steps > max_steps:
            raise ValueError("steps above max_steps")
        _check_state(state)

        current = state
        for _ in range(steps):
            current = next_chain(current)
        result[session] = current
    return result
