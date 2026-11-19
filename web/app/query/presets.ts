import { PresetQuery } from "./types";

export const STANDARD_PREFIXES = `PREFIX cve:    <http://w3id.org/sepses/vocab/ref/cve#>
PREFIX cpe:    <http://w3id.org/sepses/vocab/ref/cpe#>
PREFIX cwe:    <http://w3id.org/sepses/vocab/ref/cwe#>
PREFIX capec:  <http://w3id.org/sepses/vocab/ref/capec#>
PREFIX attck:  <http://w3id.org/sepses/vocab/ref/attack#>
PREFIX icsa:   <http://w3id.org/sepses/vocab/ref/icsa#>
PREFIX epss:   <http://w3id.org/sepses/vocab/ref/epss#>
PREFIX d3fend: <http://d3fend.mitre.org/ontologies/d3fend.owl#>
PREFIX rdfs:   <http://www.w3.org/2000/01/rdf-schema#>
PREFIX socrates: <http://w3id.org/sepses/ontology/socrates#>`;

export const PRESETS: PresetQuery[] = [
  {
    id: "cve_scores",
    name: "1. Recent High Severity CVEs",
    query: `${STANDARD_PREFIXES}\n\nSELECT ?cveId ?baseScore ?severity ?pubDate\nWHERE {\n  GRAPH <http://w3id.org/sepses/graph/cve> {\n    ?cve cve:id ?cveId ; cve:baseScore ?baseScore ; cve:severity ?severity ; cve:published ?pubDate .\n    FILTER(?baseScore >= 9.0)\n  }\n}\nORDER BY DESC(?pubDate)\nLIMIT 25`,
  },
  {
    id: "cve_cwe_capec",
    name: "2. CVE to Weakness & Attack Patterns",
    query: `${STANDARD_PREFIXES}\n\nSELECT ?cveId ?cweName ?capecName\nWHERE {\n  GRAPH <http://w3id.org/sepses/graph/cve> { ?cve cve:id ?cveId . }\n  GRAPH <http://w3id.org/sepses/graph/cve2cwe> { ?cve cve:hasCWE ?cweNode . }\n  GRAPH <http://w3id.org/sepses/graph/cwe> { ?cweNode cwe:name ?cweName . }\n  GRAPH <http://w3id.org/sepses/graph/cwe2capec> { ?cweNode cwe:hasCAPEC ?capecNode . }\n  GRAPH <http://w3id.org/sepses/graph/capec> { ?capecNode capec:name ?capecName . }\n}\nLIMIT 25`,
  },
  {
    id: "cve_attck_direct",
    name: "3. Direct CVE to ATT&CK Techniques",
    query: `${STANDARD_PREFIXES}\n\nSELECT ?cveId ?techniqueId ?techniqueName\nWHERE {\n  GRAPH <http://w3id.org/sepses/graph/cve2attck> { ?cve cve:relatedAttackPattern ?attck . }\n  GRAPH <http://w3id.org/sepses/graph/cve> { ?cve cve:id ?cveId . }\n  ?attck attck:techniqueId ?techniqueId ; attck:name ?techniqueName .\n}\nLIMIT 25`,
  },
  {
    id: "cve_d3fend_direct",
    name: "4. Direct CVE to D3FEND Countermeasures",
    query: `${STANDARD_PREFIXES}\n\nSELECT ?cveId ?defTechLabel ?defTech\nWHERE {\n  GRAPH <http://w3id.org/sepses/graph/cve2d3fend> { ?cve cve:hasCountermeasure ?defTech . }\n  GRAPH <http://w3id.org/sepses/graph/cve> { ?cve cve:id ?cveId . }\n  GRAPH <http://w3id.org/sepses/graph/d3fend> { ?defTech rdfs:label ?defTechLabel . }\n}\nLIMIT 25`,
  },
  {
    id: "cpe_vendors",
    name: "5. Products & Vendors (CPE)",
    query: `${STANDARD_PREFIXES}\n\nSELECT DISTINCT ?vendor ?product ?version\nWHERE {\n  GRAPH <http://w3id.org/sepses/graph/cpe> {\n    ?cpe cpe:vendor ?vendor ; cpe:product ?product ; cpe:version ?version .\n    FILTER(regex(?vendor, "apache", "i"))\n  }\n}\nLIMIT 25`,
  },
  {
    id: "fts_bif_contains",
    name: "6. Full-Text Search (bif:contains)",
    query: `${STANDARD_PREFIXES}\n\nSELECT ?cveId ?description\nWHERE {\n  GRAPH <http://w3id.org/sepses/graph/cve> {\n    ?cve cve:id ?cveId ; cve:description ?description .\n    FILTER(bif:contains(?description, "'sql' AND 'injection'"))\n  }\n}\nLIMIT 25`,
  },
  {
    id: "attck_d3fend",
    name: "7. ATT&CK Techniques & D3FEND Countermeasures",
    query: `${STANDARD_PREFIXES}\n\nSELECT ?techniqueId ?techniqueName ?defTechLabel\nWHERE {\n  GRAPH <http://w3id.org/sepses/graph/d3fend2attck> { ?defTech d3fend:counters ?attckNode . }\n  GRAPH <http://w3id.org/sepses/graph/d3fend> { ?defTech rdfs:label ?defTechLabel . }\n  GRAPH <http://w3id.org/sepses/graph/attck_enterprise> {\n    ?attckNode attck:techniqueId ?techniqueId ; attck:name ?techniqueName .\n  }\n}\nLIMIT 25`,
  },
  {
    id: "reasoning_weakness",
    name: "8. Inferred Inverse: cwe:isWeaknessOf",
    query: `DEFINE input:inference "socrates"\n${STANDARD_PREFIXES}\n\nSELECT ?cwe ?cve WHERE { ?cwe cwe:isWeaknessOf ?cve . } LIMIT 25`,
  },
  {
    id: "reasoning_attck_cve",
    name: "9. Inferred Inverse: attck:relatedCVE",
    query: `DEFINE input:inference "socrates"\n${STANDARD_PREFIXES}\n\nSELECT ?technique ?cve WHERE { ?technique attck:relatedCVE ?cve . } LIMIT 25`,
  },
  {
    id: "reasoning_d3fend_cve",
    name: "10. Inferred Inverse: d3fend:mitigatesCVE",
    query: `DEFINE input:inference "socrates"\n${STANDARD_PREFIXES}\n\nSELECT ?defTech ?cve WHERE { ?defTech d3fend:mitigatesCVE ?cve . } LIMIT 25`,
  },
  {
    id: "reasoning_countered",
    name: "11. Inferred Inverse: attck:counteredBy",
    query: `DEFINE input:inference "socrates"\n${STANDARD_PREFIXES}\n\nSELECT ?attackTechnique ?defensiveMeasure WHERE { ?attackTechnique attck:counteredBy ?defensiveMeasure . } LIMIT 25`,
  },
  {
    id: "reasoning_taxonomy",
    name: "12. Inferred SubClassOf: socrates:SecurityEntity",
    query: `DEFINE input:inference "socrates"\n${STANDARD_PREFIXES}\n\nSELECT ?entity ?type WHERE { ?entity a socrates:SecurityEntity ; a ?type . } LIMIT 25`,
  },
  {
    id: "graph_stats",
    name: "13. Total Triples by Named Graph",
    query: `SELECT ?graph (COUNT(*) AS ?triples)\nWHERE { GRAPH ?graph { ?s ?p ?o . } }\nGROUP BY ?graph\nORDER BY DESC(?triples)`,
  },
  {
    id: "mobile_mitigations",
    name: "14. Mobile Techniques: Mitigations & Observed Malware",
    query: `${STANDARD_PREFIXES}\n\nSELECT ?techniqueId ?techniqueName (GROUP_CONCAT(DISTINCT ?mitigation; separator="; ") AS ?mitigations) (COUNT(DISTINCT ?software) AS ?malwareCount)\nWHERE {\n  GRAPH <http://w3id.org/sepses/graph/attck_mobile> { ?t attck:techniqueId ?techniqueId ; attck:name ?techniqueName . }\n  OPTIONAL {\n    GRAPH <http://w3id.org/sepses/graph/mitigation2attck> { ?m attck:mitigates ?t . }\n    ?m attck:mitreId ?mid ; attck:name ?mname .\n    BIND(CONCAT(?mid, " ", ?mname) AS ?mitigation)\n  }\n  OPTIONAL { GRAPH <http://w3id.org/sepses/graph/software2attck> { ?software attck:uses ?t . } }\n}\nGROUP BY ?techniqueId ?techniqueName\nORDER BY DESC(?malwareCount)\nLIMIT 25`,
  },
];
