import modules.vector.hybrid as hybrid


def _fake_search(sim):
    return lambda query, entity_types=None, top_k=5: [
        {"id": "D3-OTP", "type": "d3fend", "name": "One-time Password", "similarity": sim, "uri": "", "document": ""}
    ]


def test_open_ended_weak_match_abstains(monkeypatch):
    monkeypatch.setattr(hybrid, "search_entities", _fake_search(0.30))
    assert hybrid.retrieve_hybrid("some made-up thing") == []


def test_type_filtered_weak_match_still_returns(monkeypatch):
    monkeypatch.setattr(hybrid, "search_entities", _fake_search(0.30))
    res = hybrid.retrieve_hybrid("prevent android lockscreen bypass", entity_types=["d3fend"])
    assert [r["id"] for r in res] == ["D3-OTP"]
