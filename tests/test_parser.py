from rdflib import Graph, Literal

from modules.parser.mapper import OntologyMapper
from modules.parser.nodes.executor import _format_literal

mapper = OntologyMapper()


def _cve(metrics):
    return {"cve": {"id": "CVE-2025-0001", "descriptions": [{"lang": "en", "value": "x"}], "metrics": metrics}}


def test_cvss_prefers_nvd_primary_over_cna_secondary():
    m = mapper.map_entity("cve", _cve({"cvssMetricV31": [
        {"type": "Secondary", "cvssData": {"baseScore": 9.8, "baseSeverity": "CRITICAL"}},
        {"type": "Primary", "cvssData": {"baseScore": 7.5, "baseSeverity": "HIGH"}},
    ]}))
    assert (m["sepses:baseScore"], m["sepses:severity"]) == (7.5, "HIGH")


def test_cvss_v40_only_cve_still_gets_a_score():
    m = mapper.map_entity("cve", _cve({"cvssMetricV40": [
        {"type": "Secondary", "cvssData": {"baseScore": 8.7, "baseSeverity": "HIGH", "vectorString": "CVSS:4.0/AV:N"}},
    ]}))
    assert (m["sepses:baseScore"], m["sepses:severity"], m["sepses:vectorString"]) == (8.7, "HIGH", "CVSS:4.0/AV:N")


def test_attck_tactics_for_all_matrices():
    for chain in ("mitre-attack", "mitre-ics-attack", "mitre-mobile-attack"):
        m = mapper.map_entity("attck_x", {
            "type": "attack-pattern", "id": "attack-pattern--1", "name": "n",
            "external_references": [{"source_name": "mitre-attack", "external_id": "T0001"}],
            "kill_chain_phases": [{"kill_chain_name": chain, "phase_name": "impact"}],
        })
        assert m["sepses:tactic"] == ["impact"], chain


def test_non_bmp_characters_round_trip_through_turtle():
    text = 'pages/1_\U0001F4F7_Timelapse.py "quoted"\nnext line'
    ttl = f"<http://e/s> <http://e/p> {_format_literal('description', text)} ."
    assert Literal(text) in set(Graph().parse(data=ttl, format="turtle").objects())
