"""The CVE->ATT&CK / CVE->D3FEND linkers must read every object of multi-object
Turtle statements (``s p o1, o2 ;``), which is how rdflib serializes link files."""

import json

from rdflib import Graph

import modules.linking.nodes.executor as ex

RES = "http://w3id.org/sepses/resource"

CWE2CAPEC = f"""@prefix cwe: <http://w3id.org/sepses/vocab/ref/cwe#> .
<{RES}/cwe/CWE-79> cwe:hasCAPEC <{RES}/capec/CAPEC-1>,
        <{RES}/capec/CAPEC-2> .
"""
CAPEC2ATTCK = f"""@prefix capec: <http://w3id.org/sepses/vocab/ref/capec#> .
<{RES}/capec/CAPEC-1> capec:hasRelatedAttackPattern <{RES}/attack/T1059> .
<{RES}/capec/CAPEC-2> capec:hasRelatedAttackPattern <{RES}/attack/T1190>,
        <{RES}/attack/T1203> .
"""
D3FEND2ATTCK = f"""@prefix d3fend: <http://d3fend.mitre.org/ontologies/d3fend.owl#> .
d3fend:InputValidation d3fend:counters <{RES}/attack/T1190>,
        <{RES}/attack/T1059.001> .
d3fend:ExploitProtection d3fend:counters <{RES}/attack/T1203> .
"""


def _setup(tmp_path, monkeypatch):
    out = tmp_path / "linking"
    stale = tmp_path / "sparql"
    out.mkdir()
    stale.mkdir()
    (out / "cwe2capec.ttl").write_text(CWE2CAPEC)
    (out / "capec2attck.ttl").write_text(CAPEC2ATTCK)
    (out / "d3fend2attck.ttl").write_text(D3FEND2ATTCK)
    # A stale copy in the load directory must not leak into fresh results.
    (stale / "capec2attck.ttl").write_text(
        f"<{RES}/capec/CAPEC-1> <http://w3id.org/sepses/vocab/ref/capec#hasRelatedAttackPattern> <{RES}/attack/T9999> .\n"
    )
    monkeypatch.setattr(ex, "LINKING_OUTPUT_DIR", out)
    monkeypatch.setattr(ex, "SPARQL_DATA_DIR", stale)

    cves = [
        {"cve": {"id": "CVE-2024-0001", "weaknesses": [{"description": [{"value": "CWE-79"}]}], "references": []}},
        {"cve": {"id": "CVE-2024-0002", "weaknesses": [],
                 "references": [{"url": "https://attack.mitre.org/techniques/T1059/001/"}]}},
        {"cve": {"id": "CVE-2024-0003", "weaknesses": [{"description": [{"value": "NVD-CWE-Other"}]}]}},
    ]
    cve_file = tmp_path / "cve.json"
    cve_file.write_text(json.dumps(cves))
    return out, cve_file


def _pairs(path):
    g = Graph().parse(str(path), format="turtle")
    return {(ex._local_id(str(s)), ex._local_id(str(o))) for s, o in g.subject_objects()}


def test_cwe_to_attck_map_reads_all_objects(tmp_path, monkeypatch):
    _setup(tmp_path, monkeypatch)
    assert ex._build_cwe_to_attck_map() == {"CWE-79": {"T1059", "T1190", "T1203"}}


def test_cve_to_attck_and_d3fend(tmp_path, monkeypatch):
    out, cve_file = _setup(tmp_path, monkeypatch)

    n = ex._link_cve_to_attck_stream(out / "cve2attck.ttl", [str(cve_file)], ex.NS_CVE.relatedAttackPattern)
    assert n == 4
    assert _pairs(out / "cve2attck.ttl") == {
        ("CVE-2024-0001", "T1059"),
        ("CVE-2024-0001", "T1190"),
        ("CVE-2024-0001", "T1203"),
        ("CVE-2024-0002", "T1059.001"),  # sub-technique URL keeps its suffix
    }

    n = ex._link_cve_to_d3fend_stream(out / "cve2d3fend.ttl", ex.NS_CVE.hasCountermeasure)
    assert n == 3
    assert _pairs(out / "cve2d3fend.ttl") == {
        ("CVE-2024-0001", "InputValidation"),
        ("CVE-2024-0001", "ExploitProtection"),
        ("CVE-2024-0002", "InputValidation"),
    }


def test_falls_back_to_load_dir_when_output_missing(tmp_path, monkeypatch):
    out, _ = _setup(tmp_path, monkeypatch)
    (out / "capec2attck.ttl").unlink()
    assert ex._load_link_pairs("capec2attck.ttl", ex.NS_CAPEC.hasRelatedAttackPattern) == {"CAPEC-1": {"T9999"}}
