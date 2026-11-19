import json

from rdflib import Graph

import modules.linking.nodes.executor as ex
from modules.parser.mapper import OntologyMapper

REF = lambda i: [{"source_name": "mitre-attack", "external_id": i}]  # noqa: E731

BUNDLE = {"objects": [
    {"type": "attack-pattern", "id": "attack-pattern--1", "name": "Lockscreen Bypass", "external_references": REF("T1461")},
    {"type": "course-of-action", "id": "course-of-action--1", "name": "Security Updates", "external_references": REF("M1001")},
    {"type": "course-of-action", "id": "course-of-action--2", "name": "Old", "external_references": REF("M9999"), "x_mitre_deprecated": True},
    {"type": "malware", "id": "malware--1", "name": "BRATA", "aliases": ["BRATA", "Brazilian RAT"], "external_references": REF("S1094")},
    {"type": "intrusion-set", "id": "intrusion-set--1", "name": "APT-X", "external_references": REF("G0001")},
    {"type": "relationship", "relationship_type": "mitigates", "source_ref": "course-of-action--1", "target_ref": "attack-pattern--1"},
    {"type": "relationship", "relationship_type": "mitigates", "source_ref": "course-of-action--2", "target_ref": "attack-pattern--1"},
    {"type": "relationship", "relationship_type": "uses", "source_ref": "malware--1", "target_ref": "attack-pattern--1"},
    {"type": "relationship", "relationship_type": "uses", "source_ref": "intrusion-set--1", "target_ref": "attack-pattern--1"},
]}


def test_mapper_keeps_mitigations_software_groups():
    m = OntologyMapper()
    mit = m.map_entity("attck_mobile", BUNDLE["objects"][1])
    assert (mit["@type"], mit["sepses:mitreId"], mit["__uri_key__"]) == ("sepses:Mitigation", "M1001", "M1001")
    sw = m.map_entity("attck_mobile", BUNDLE["objects"][3])
    assert (sw["@type"], sw["sepses:mitreId"], sw["sepses:softwareType"], sw["sepses:alias"]) == (
        "sepses:Software", "S1094", "malware", ["Brazilian RAT"])
    assert m.map_entity("attck_mobile", BUNDLE["objects"][2]) == {}  # deprecated mitigation dropped
    assert m.map_entity("attck_mobile", BUNDLE["objects"][4])["@type"] == "sepses:Group"


def _links(tmp_path, link_type):
    src = tmp_path / "attck_mobile.json"
    src.write_text(json.dumps(BUNDLE))
    out = tmp_path / f"{link_type}.ttl"
    rel, types = ex.ATTCK_RELATIONSHIP_LINKS[link_type]
    pred = ex.NS_ATTCK_VOCAB.mitigates if rel == "mitigates" else ex.NS_ATTCK_VOCAB.uses
    ex._link_attck_relationships(out, [str(src)], pred, rel, types)
    return {(ex._local_id(str(s)), ex._local_id(str(o))) for s, o in Graph().parse(str(out)).subject_objects()}


def test_relationship_links(tmp_path):
    assert _links(tmp_path, "mitigation2attck") == {("M1001", "T1461")}  # deprecated M9999 excluded
    assert _links(tmp_path, "software2attck") == {("S1094", "T1461")}
    assert _links(tmp_path, "group2attck") == {("G0001", "T1461")}


def test_enterprise_twins_link_exact_names_only(tmp_path):
    def bundle(items):
        return {"objects": [
            {"type": "attack-pattern", "id": f"attack-pattern--{tid}", "name": name, "external_references": REF(tid)}
            for tid, name in items
        ]}
    ent = tmp_path / "attck_enterprise.json"
    mob = tmp_path / "attck_mobile.json"
    ent.write_text(json.dumps(bundle([("T1056.001", "Keylogging"), ("T1499", "Endpoint Denial of Service")])))
    mob.write_text(json.dumps(bundle([("T1417.001", "keylogging"), ("T1461", "Lockscreen Bypass")])))
    out = tmp_path / "twin2attck.ttl"
    n = ex._link_enterprise_twins(out, [str(ent), str(mob)], ex.NS_ATTCK_VOCAB.enterpriseTwin)
    pairs = {(ex._local_id(str(s)), ex._local_id(str(o))) for s, o in Graph().parse(str(out)).subject_objects()}
    assert n == 1 and pairs == {("T1417.001", "T1056.001")}  # case-insensitive; no twin for Lockscreen Bypass
