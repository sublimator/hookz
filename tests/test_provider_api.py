"""Provider-neutral HookRuntime seams used by non-C guest runtimes."""

import pytest

from hookz.runtime import HookAccepted, HookRuntime


class Memory:
    def __init__(self, data: bytes):
        self.data = bytearray(data)

    def read(self, _store, start: int, end: int):
        return self.data[start:end]

    def write(self, _store, data: bytes, start: int):
        self.data[start:start + len(data)] = data

    def data_len(self, _store):
        return len(self.data)


def test_foreign_provider_can_bind_memory_and_dispatch_raw_accept():
    rt = HookRuntime()
    memory = Memory(b"hello from another guest")
    store = object()

    with rt.bind_memory(memory, store):
        with pytest.raises(HookAccepted) as accepted:
            rt.dispatch_host_call("accept", 0, 5, 17)

    assert accepted.value.msg == b"hello"
    assert accepted.value.code == 17
    assert [(call.name, call.args) for call in rt.call_log] == [
        ("accept", (0, 5, 17)),
    ]
    assert rt._memory is None
    assert rt._store is None


def test_foreign_provider_dispatch_uses_handler_overrides_and_call_evidence():
    rt = HookRuntime()
    rt.handlers["ledger_seq"] = lambda: 321

    assert rt.dispatch_host_call("ledger_seq") == 321
    assert rt.call_log[0].name == "ledger_seq"
    assert rt.call_log[0].result == 321
