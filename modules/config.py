import os
from pathlib import Path

from dotenv import load_dotenv

load_dotenv()

BASE_DIR = Path(__file__).resolve().parent.parent
CACHE_DIR = BASE_DIR / "modules" / "fetcher" / "cache"
CACHE_DIR.mkdir(exist_ok=True, parents=True)
PARSER_OUTPUT_DIR = BASE_DIR / "modules" / "parser" / "output"
LINKING_OUTPUT_DIR = BASE_DIR / "modules" / "linking" / "output"
VALIDATION_REPORTS_DIR = BASE_DIR / "modules" / "validation" / "output" / "reports"
SHACL_SHAPES_DIR = BASE_DIR / "modules" / "validation" / "shapes"
ONTOLOGY_DIR = BASE_DIR / "ontology"
SPARQL_DATA_DIR = BASE_DIR / "sparql" / "data"
VECTOR_DIR = BASE_DIR / "modules" / "vector"
CHROMA_DB_DIR = VECTOR_DIR / "db"
CHROMA_DB_DIR.mkdir(parents=True, exist_ok=True)
COLLECTION_SECURITY_ENTITIES = "security_entities"
EMBEDDING_BATCH_SIZE = 100
DEFAULT_CVE_INDEX_LIMIT = 5000

NVD_API_KEY = os.getenv("NVD_API_KEY")
NVD_PAGE_SIZE = 2000
NVD_MAX_DEMO = int(os.getenv("NVD_MAX_DEMO", "0")) or None
NVD_DELTA_DAYS = int(os.getenv("NVD_DELTA_DAYS", "0"))
NVD_SYNC_FILE = CACHE_DIR / "nvd_sync.json"

NVD_CVE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
NVD_CPE_URL = "https://services.nvd.nist.gov/rest/json/cpes/2.0"

CWE_DOWNLOAD_PAGE = "https://cwe.mitre.org/data/downloads.html"
CWE_URL = "https://cwe.mitre.org/data/xml/cwec_latest.xml.zip"

CAPEC_DOWNLOAD_PAGE = "https://capec.mitre.org/data/downloads.html"
CAPEC_URL = "https://capec.mitre.org/data/xml/capec_latest.xml"

ICSA_FEED_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
EPSS_FEED_URL = "https://epss.cyentia.com/epss_scores-current.csv.gz"
D3FEND_ONTOLOGY_URL = "https://d3fend.mitre.org/ontologies/d3fend.ttl"
D3FEND_MAPPINGS_URL = (
    "https://d3fend.mitre.org/ontologies/d3fend/1.6.0/d3fend-full-mappings.json"
)

ATTCK_DIRECT_URLS = {
    "attck_enterprise": "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack.json",
    "attck_ics": "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/ics-attack/ics-attack.json",
    "attck_mobile": "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/mobile-attack/mobile-attack.json",
}
ATTCK_VERSION_URLS = {
    "attck_enterprise": "https://api.github.com/repos/mitre-attack/attack-stix-data/commits?path=enterprise-attack/enterprise-attack.json&per_page=1",
    "attck_ics": "https://api.github.com/repos/mitre-attack/attack-stix-data/commits?path=ics-attack/ics-attack.json&per_page=1",
    "attck_mobile": "https://api.github.com/repos/mitre-attack/attack-stix-data/commits?path=mobile-attack/mobile-attack.json&per_page=1",
}

VOCAB_NS = {
    "cve": "http://w3id.org/sepses/vocab/ref/cve#",
    "cwe": "http://w3id.org/sepses/vocab/ref/cwe#",
    "cpe": "http://w3id.org/sepses/vocab/ref/cpe#",
    "capec": "http://w3id.org/sepses/vocab/ref/capec#",
    "icsa": "http://w3id.org/sepses/vocab/ref/icsa#",
    "attck_enterprise": "http://w3id.org/sepses/vocab/ref/attack#",
    "attck_ics": "http://w3id.org/sepses/vocab/ref/attack#",
    "attck_mobile": "http://w3id.org/sepses/vocab/ref/attack#",
    "epss": "http://w3id.org/sepses/vocab/ref/epss#",
    "d3fend": "http://d3fend.mitre.org/ontologies/d3fend.owl#",
}

NAMESPACES = {
    "cve": "http://w3id.org/sepses/vocab/ref/cve#",
    "cwe": "http://w3id.org/sepses/vocab/ref/cwe#",
    "capec": "http://w3id.org/sepses/vocab/ref/capec#",
    "cpe": "http://w3id.org/sepses/vocab/ref/cpe#",
    "cvss": "http://w3id.org/sepses/vocab/ref/cvss#",
    "attck": "http://w3id.org/sepses/vocab/ref/attack#",
    "icsa": "http://w3id.org/sepses/vocab/ref/icsa#",
    "epss": "http://w3id.org/sepses/vocab/ref/epss#",
    "d3fend": "http://d3fend.mitre.org/ontologies/d3fend.owl#",
    "rdf": "http://www.w3.org/1999/02/22-rdf-syntax-ns#",
    "rdfs": "http://www.w3.org/2000/01/rdf-schema#",
    "xsd": "http://www.w3.org/2001/XMLSchema#",
}

RESOURCE_BASE = "http://w3id.org/sepses/resource/"

RESOURCE_BASE_MAP = {
    "cve": "http://w3id.org/sepses/resource/cve/",
    "cwe": "http://w3id.org/sepses/resource/cwe/",
    "capec": "http://w3id.org/sepses/resource/capec/",
    "cpe": "http://w3id.org/sepses/resource/cpe/",
    "attck": "http://w3id.org/sepses/resource/attack/",
    "icsa": "http://w3id.org/sepses/resource/icsa/",
    "epss": "http://w3id.org/sepses/resource/epss/",
    "d3fend": "http://d3fend.mitre.org/ontologies/d3fend.owl#",
}

LINKING_RULES = [
    {
        "link_type": "cve2cwe",
        "subject_src": "cve",
        "object_src": "cwe",
        "predicate": "cve:hasCWE",
        "description": "CVE vulnerability linked to CWE weakness",
    },
    {
        "link_type": "cve2cpe",
        "subject_src": "cve",
        "object_src": "cpe",
        "predicate": "cve:hasCPE",
        "description": "CVE vulnerability linked to affected CPE product",
    },
    {
        "link_type": "cwe2capec",
        "subject_src": "cwe",
        "object_src": "capec",
        "predicate": "cwe:hasCAPEC",
        "description": "CWE weakness linked to CAPEC attack pattern",
    },
    {
        "link_type": "capec2attck",
        "subject_src": "capec",
        "object_src": "attck",
        "predicate": "capec:hasRelatedAttackPattern",
        "description": "CAPEC attack pattern linked to MITRE ATT&CK technique",
    },
    {
        "link_type": "icsa2cve",
        "subject_src": "icsa",
        "object_src": "cve",
        "predicate": "icsa:hasCVE",
        "description": "ICSA advisory linked to CVE vulnerability",
    },
    {
        "link_type": "cve2epss",
        "subject_src": "cve",
        "object_src": "epss",
        "predicate": "cve:hasEPSS",
        "description": "CVE vulnerability linked to EPSS exploit probability scores",
    },
    {
        "link_type": "d3fend2attck",
        "subject_src": "d3fend",
        "object_src": "attck",
        "predicate": "d3fend:counters",
        "description": "MITRE D3FEND defensive countermeasure linked to ATT&CK technique",
    },
    {
        "link_type": "mitigation2attck",
        "subject_src": "attck",
        "object_src": "attck",
        "predicate": "attck:mitigates",
        "description": "Official MITRE ATT&CK mitigation (M####) for a technique",
    },
    {
        "link_type": "software2attck",
        "subject_src": "attck",
        "object_src": "attck",
        "predicate": "attck:uses",
        "description": "Malware or tool (S####) observed using an ATT&CK technique",
    },
    {
        "link_type": "group2attck",
        "subject_src": "attck",
        "object_src": "attck",
        "predicate": "attck:uses",
        "description": "Threat group (G####) observed using an ATT&CK technique",
    },
    {
        "link_type": "twin2attck",
        "subject_src": "attck",
        "object_src": "attck",
        "predicate": "attck:enterpriseTwin",
        "description": "Mobile/ICS technique linked to the Enterprise technique with the identical name",
    },
    {
        "link_type": "cve2attck",
        "subject_src": "cve",
        "object_src": "attck",
        "predicate": "cve:relatedAttackPattern",
        "description": "CVE vulnerability directly linked to MITRE ATT&CK technique",
    },
    {
        "link_type": "cve2d3fend",
        "subject_src": "cve",
        "object_src": "d3fend",
        "predicate": "cve:hasCountermeasure",
        "description": "CVE vulnerability linked to D3FEND defensive countermeasures",
    },
]

VIRTUOSO_HOST = os.environ.get("VIRTUOSO_HOST", "localhost")
VIRTUOSO_SPARQL = f"http://{VIRTUOSO_HOST}:8890/sparql"
VIRTUOSO_CONTAINER = os.environ.get("VIRTUOSO_CONTAINER", "cskg-sparql")
GRAPH_BASE = "http://w3id.org/sepses/graph/"
ONTOLOGY_GRAPH = "http://w3id.org/sepses/graph/ontology"
INFERENCE_RULE_SET = "cskg"


class _FetcherRegistry(dict):
    def __init__(self):
        super().__init__()
        self._initialized = False

    def _init(self):
        if not self._initialized:
            self._initialized = True
            from modules.fetcher.fetchers.attck import ATTCKFetcher
            from modules.fetcher.fetchers.d3fend import D3FENDFetcher
            from modules.fetcher.fetchers.epss import EPSSFetcher
            from modules.fetcher.fetchers.icsa import ICSAFetcher
            from modules.fetcher.fetchers.mitre import CAPECFetcher, CWEFetcher
            from modules.fetcher.fetchers.nvd import CPEFetcher, CVEFetcher

            self.update(
                {
                    "cwe": lambda: CWEFetcher(),
                    "capec": lambda: CAPECFetcher(),
                    "attck_enterprise": lambda: ATTCKFetcher("enterprise"),
                    "attck_ics": lambda: ATTCKFetcher("ics"),
                    "attck_mobile": lambda: ATTCKFetcher("mobile"),
                    "icsa": lambda: ICSAFetcher(),
                    "epss": lambda: EPSSFetcher(),
                    "d3fend": lambda: D3FENDFetcher(),
                    "cve": lambda: CVEFetcher(),
                    "cpe": lambda: CPEFetcher(),
                }
            )

    def get(self, key, default=None):
        self._init()
        return super().get(key, default)

    def keys(self):
        self._init()
        return super().keys()

    def values(self):
        self._init()
        return super().values()

    def items(self):
        self._init()
        return super().items()

    def __iter__(self):
        self._init()
        return super().__iter__()

    def __getitem__(self, key):
        self._init()
        return super().__getitem__(key)

    def __len__(self):
        self._init()
        return super().__len__()


FETCHER_REGISTRY = _FetcherRegistry()
