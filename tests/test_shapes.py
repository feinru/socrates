from rdflib import Graph
from pyshacl import validate

from modules.config import SHACL_SHAPES_DIR

PREFIX = "@prefix cve: <http://w3id.org/sepses/vocab/ref/cve#> .\n"
CVE = "<http://w3id.org/sepses/resource/cve/CVE-2024-0001>"


def _shapes():
    g = Graph()
    for f in sorted(SHACL_SHAPES_DIR.glob("*.ttl")):
        g.parse(str(f), format="turtle")
    return g


def _conforms(ttl):
    return validate(Graph().parse(data=PREFIX + ttl, format="turtle"), shacl_graph=_shapes())[0]


def test_valid_cve_links_conform():
    assert _conforms(
        f"{CVE} cve:relatedAttackPattern <http://w3id.org/sepses/resource/attack/T1059.001> ;"
        " cve:hasCountermeasure <http://d3fend.mitre.org/ontologies/d3fend.owl#InputValidation> ."
    )


def test_bad_attack_target_violates():
    assert not _conforms(f"{CVE} cve:relatedAttackPattern <http://example.org/T1059> .")


def test_bad_countermeasure_target_violates():
    assert not _conforms(f"{CVE} cve:hasCountermeasure <http://w3id.org/sepses/resource/attack/T1059> .")


def test_bad_subject_violates():
    assert not _conforms(
        "<http://example.org/x> cve:relatedAttackPattern <http://w3id.org/sepses/resource/attack/T1059> ."
    )
