import sys
from pathlib import Path

import requests

parent_dir = Path(__file__).resolve().parent.parent
if str(parent_dir) not in sys.path:
    sys.path.insert(0, str(parent_dir))

from modules.config import VIRTUOSO_HOST
from modules.config import VIRTUOSO_SPARQL as SPARQL_ENDPOINT


def query(sparql: str, description: str) -> bool:
    print(f"\n[{description}]")
    print(f"Query: {sparql[:80]}...")
    try:
        resp = requests.get(
            SPARQL_ENDPOINT,
            params={"query": sparql, "format": "application/sparql-results+json"},
            timeout=60,
        )
    except requests.RequestException as e:
        print(f"[FAIL] Request error: {e}")
        return False
    if resp.status_code != 200:
        print(f"[FAIL] Error status: {resp.status_code}")
        return False
    bindings = resp.json()["results"]["bindings"]
    for row in bindings[:3]:
        print("->", {k: v["value"] for k, v in row.items()})
    print(f"[OK] {len(bindings)} results returned")
    return True


def main():
    print("[SPARQL] Verification: SEPSES Cyber-KG")
    tests = [
        (
            "SELECT (COUNT(*) AS ?total) WHERE { ?s ?p ?o }",
            "Total triples across all graphs",
        ),
        ("SELECT DISTINCT ?g WHERE { GRAPH ?g { ?s ?p ?o } }", "List named graphs"),
        (
            "SELECT ?cve ?desc WHERE {\n               GRAPH <http://w3id.org/sepses/graph/cve> {\n                 ?cve a <http://w3id.org/sepses/vocab/ref/cve#CVE> ;\n                      <http://w3id.org/sepses/vocab/ref/cve#id> ?desc .\n               }\n             } LIMIT 3",
            "Sample CVE entries",
        ),
        (
            "SELECT ?cwe ?name WHERE {\n               GRAPH <http://w3id.org/sepses/graph/cwe> {\n                 ?cwe a <http://w3id.org/sepses/vocab/ref/cwe#CWE> ;\n                       <http://w3id.org/sepses/vocab/ref/cwe#name> ?name .\n               }\n             } LIMIT 3",
            "Sample CWE entries",
        ),
        (
            "SELECT ?capec ?attck WHERE {\n               GRAPH <http://w3id.org/sepses/graph/capec2attck> {\n                 ?capec <http://w3id.org/sepses/vocab/ref/capec#hasRelatedAttackPattern> ?attck .\n               }\n             } LIMIT 3",
            "Sample CAPEC to ATT&CK links",
        ),
        (
            "SELECT ?icsa ?cve WHERE {\n               GRAPH <http://w3id.org/sepses/graph/icsa2cve> {\n                 ?icsa <http://w3id.org/sepses/vocab/ref/icsa#hasCVE> ?cve .\n               }\n             } LIMIT 3",
            "Sample ICSA to CVE links",
        ),
        (
            "SELECT ?tech ?name WHERE {\n               GRAPH <http://w3id.org/sepses/graph/attck_mobile> {\n                 ?tech <http://w3id.org/sepses/vocab/ref/attack#techniqueId> ?name .\n               }\n             } LIMIT 3",
            "Sample ATT&CK Mobile techniques",
        ),
        (
            "SELECT ?epss ?score WHERE {\n               GRAPH <http://w3id.org/sepses/graph/epss> {\n                 ?epss <http://w3id.org/sepses/vocab/ref/epss#epssScore> ?score .\n               }\n             } LIMIT 3",
            "Sample EPSS predictions",
        ),
        (
            "SELECT ?cve ?epss WHERE {\n               GRAPH <http://w3id.org/sepses/graph/cve2epss> {\n                 ?cve <http://w3id.org/sepses/vocab/ref/cve#hasEPSS> ?epss .\n               }\n             } LIMIT 3",
            "Sample CVE to EPSS links",
        ),
        (
            "SELECT ?defTech ?attck WHERE {\n               GRAPH <http://w3id.org/sepses/graph/d3fend2attck> {\n                 ?defTech <http://d3fend.mitre.org/ontologies/d3fend.owl#counters> ?attck .\n               }\n             } LIMIT 3",
            "Sample D3FEND countermeasures to ATT&CK techniques",
        ),
        (
            "SELECT ?cve ?attck WHERE {\n               GRAPH <http://w3id.org/sepses/graph/cve2attck> {\n                 ?cve <http://w3id.org/sepses/vocab/ref/cve#relatedAttackPattern> ?attck .\n               }\n             } LIMIT 3",
            "Sample CVE to ATT&CK direct links",
        ),
        (
            "SELECT ?cve ?defTech WHERE {\n               GRAPH <http://w3id.org/sepses/graph/cve2d3fend> {\n                 ?cve <http://w3id.org/sepses/vocab/ref/cve#hasCountermeasure> ?defTech .\n               }\n             } LIMIT 3",
            "Sample CVE to D3FEND direct countermeasures",
        ),
        (
            "SELECT ?cve ?desc WHERE {\n               GRAPH <http://w3id.org/sepses/graph/cve> {\n                 ?cve <http://w3id.org/sepses/vocab/ref/cve#description> ?desc .\n                 FILTER(bif:contains(?desc, \"'sql' AND 'injection'\"))\n               }\n             } LIMIT 3",
            "Full-Text Search (bif:contains)",
        ),
        (
            "SELECT ?m ?t WHERE {\n               GRAPH <http://w3id.org/sepses/graph/mitigation2attck> {\n                 ?m <http://w3id.org/sepses/vocab/ref/attack#mitigates> ?t .\n               }\n             } LIMIT 3",
            "Sample ATT&CK mitigations to techniques",
        ),
        (
            "SELECT ?s ?t WHERE {\n               GRAPH <http://w3id.org/sepses/graph/software2attck> {\n                 ?s <http://w3id.org/sepses/vocab/ref/attack#uses> ?t .\n               }\n             } LIMIT 3",
            "Sample malware/tools observed using techniques",
        ),
        (
            "SELECT (COUNT(*) AS ?total) WHERE {\n               GRAPH <http://w3id.org/sepses/graph/ontology> { ?s ?p ?o }\n             }",
            "CSKG Core Ontology Graph",
        ),
        (
            'DEFINE input:inference "cskg"\n             SELECT ?cwe ?cve WHERE {\n               ?cwe <http://w3id.org/sepses/vocab/ref/cwe#isWeaknessOf> ?cve .\n             } LIMIT 3',
            "Semantic Reasoning: Inferred inverseOf (cwe:isWeaknessOf <- cve:hasCWE)",
        ),
        (
            'DEFINE input:inference "cskg"\n             SELECT ?tech ?cve WHERE {\n               ?tech <http://w3id.org/sepses/vocab/ref/attack#relatedCVE> ?cve .\n             } LIMIT 3',
            "Semantic Reasoning: Inferred inverseOf (attck:relatedCVE <- cve:relatedAttackPattern)",
        ),
        (
            'DEFINE input:inference "cskg"\n             SELECT ?defTech ?cve WHERE {\n               ?defTech <http://d3fend.mitre.org/ontologies/d3fend.owl#mitigatesCVE> ?cve .\n             } LIMIT 3',
            "Semantic Reasoning: Inferred inverseOf (d3fend:mitigatesCVE <- cve:hasCountermeasure)",
        ),
        (
            'DEFINE input:inference "cskg"\n             SELECT ?tech ?m WHERE {\n               ?tech <http://w3id.org/sepses/vocab/ref/attack#mitigatedBy> ?m .\n             } LIMIT 3',
            "Semantic Reasoning: Inferred inverseOf (attck:mitigatedBy <- attck:mitigates)",
        ),
        (
            'DEFINE input:inference "cskg"\n             SELECT ?tech ?defTech WHERE {\n               ?tech <http://w3id.org/sepses/vocab/ref/attack#counteredBy> ?defTech .\n             } LIMIT 3',
            "Semantic Reasoning: Inferred inverseOf (attck:counteredBy <- d3fend:counters)",
        ),
        (
            'DEFINE input:inference "cskg"\n             SELECT ?entity WHERE {\n               ?entity a <http://w3id.org/sepses/ontology/cskg#SecurityEntity> .\n             } LIMIT 3',
            "Semantic Reasoning: SubClassOf taxonomy (cskg:SecurityEntity)",
        ),
    ]
    passed = 0
    for sparql, desc in tests:
        if query(sparql, desc):
            passed += 1
    print(f"\nTests passed: {passed}/{len(tests)}")
    print(f"Endpoint URL : {SPARQL_ENDPOINT}")
    print(f"Web UI       : http://{VIRTUOSO_HOST}:8890/conductor\n")


if __name__ == "__main__":
    main()
