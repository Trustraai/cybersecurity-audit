from secaudit_workbench.hashchain import GENESIS, file_hash, link, verify_chain


def test_link_deterministic():
    a = link(None, {"x": 1})
    b = link(None, {"x": 1})
    assert a == b
    assert a != GENESIS


def test_verify_chain_passes_when_untampered():
    entries = []
    prev = None
    for i in range(4):
        payload = {"i": i}
        h = link(prev, payload)
        entries.append((payload, h))
        prev = h
    ok, break_at = verify_chain(entries)
    assert ok is True
    assert break_at == -1


def test_verify_chain_detects_tampering():
    entries = []
    prev = None
    for i in range(3):
        payload = {"i": i}
        h = link(prev, payload)
        entries.append((payload, h))
        prev = h
    entries[1] = ({"i": 999}, entries[1][1])
    ok, break_at = verify_chain(entries)
    assert ok is False
    assert break_at == 1


def test_file_hash():
    assert file_hash(b"hello") == file_hash(b"hello")
    assert file_hash(b"hello") != file_hash(b"world")
