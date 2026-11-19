from modules.vector import extractor as ex

V = "http://w3id.org/sepses/vocab/ref/cve#"


def _cve(i, year, desc='plain'):
    return (f'<http://w3id.org/sepses/resource/cve/CVE-{year}-{i}> a <{V}CVE> ;\n'
            f'    <{V}id> "CVE-{year}-{i}" ;\n'
            f'    <{V}description> "{desc}" ;\n'
            f'    <{V}published> "{year}-01-01T00:00:00"^^<http://www.w3.org/2001/XMLSchema#dateTime> .\n')


def test_literal_handles_escaped_quotes():
    block = '<http://x/p> "uses \\"eval\\" on\\ninput" ;'
    assert ex._literal(block, "http://x/p") == 'uses "eval" on\ninput'


def test_cve_selection_prefers_kev_then_recent(tmp_path, monkeypatch):
    ttl = tmp_path / "cve.ttl"
    ttl.write_text(_cve(1, 1999) + _cve(2, 2001) + _cve(3, 2025) + _cve(4, 2026, 'has \\"quote\\"'))
    monkeypatch.setattr(ex, "_kev_cve_ids", lambda: {"CVE-1999-1"})
    got = {c["id"]: c for c in ex.extract_cve_entities(ttl, limit=2)}
    assert set(got) == {"CVE-1999-1", "CVE-2026-4"}
    assert got["CVE-2026-4"]["description"] == 'has "quote"'


def test_no_limit_yields_everything(tmp_path, monkeypatch):
    ttl = tmp_path / "cve.ttl"
    ttl.write_text(_cve(1, 1999) + _cve(2, 2001))
    monkeypatch.setattr(ex, "_kev_cve_ids", lambda: set())
    assert [c["id"] for c in ex.extract_cve_entities(ttl)] == ["CVE-1999-1", "CVE-2001-2"]
