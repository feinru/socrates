import collections
import re
import traceback
import xml.etree.ElementTree as ET
from pathlib import Path

import ijson
import orjson
from rdflib import Graph, Namespace, URIRef

from modules.config import (
    CACHE_DIR,
    LINKING_OUTPUT_DIR,
    NAMESPACES,
    SPARQL_DATA_DIR,
)
from modules.config import (
    RESOURCE_BASE_MAP as RESOURCE_BASE,
)

from ..state import LinkingState

NS_CVE = Namespace(NAMESPACES["cve"])
NS_CWE = Namespace(NAMESPACES["cwe"])
NS_CAPEC = Namespace(NAMESPACES["capec"])
NS_D3FEND = Namespace(NAMESPACES["d3fend"])
NS_ATTCK_VOCAB = Namespace(NAMESPACES["attck"])


# link_type -> (STIX relationship_type, source object types) taken from the ATT&CK bundles.
ATTCK_RELATIONSHIP_LINKS = {
    "mitigation2attck": ("mitigates", ("course-of-action",)),
    "software2attck": ("uses", ("malware", "tool")),
    "group2attck": ("uses", ("intrusion-set",)),
}


def executor(state: LinkingState) -> LinkingState:
    task = state.get("current_task")
    if not task:
        print("[Linking] No task to execute.")
        linked_results = state.get("linked_results", [])
        link_plan = state.get("link_plan", [])
        next_task = link_plan.pop(0) if link_plan else {}
        return {
            "link_plan": link_plan,
            "current_task": next_task,
            "linked_results": linked_results,
        }
    link_type = task["link_type"]
    predicate_str = task["predicate"]
    subject_files = task.get("subject_files", [])
    print(f"\n[Linking] Processing: {link_type}")
    print(f"[{link_type}] Predicate: {predicate_str}")
    result = {
        "link_type": link_type,
        "predicate": predicate_str,
        "status": "failed",
        "triples_count": 0,
        "output_file": None,
        "error": None,
    }
    try:
        g = Graph()
        for prefix, uri in NAMESPACES.items():
            g.bind(prefix, Namespace(uri))
        predicate_uri = _resolve_predicate(predicate_str)
        triples_count = 0
        out_dir = LINKING_OUTPUT_DIR
        out_file = out_dir / f"{link_type}.ttl"
        is_streamed = False

        if link_type == "cve2cwe":
            triples_count = _link_cve_to_cwe_stream(
                out_file, subject_files, predicate_uri
            )
            is_streamed = True
        elif link_type == "cve2cpe":
            triples_count = _link_cve_to_cpe_stream(
                out_file, subject_files, predicate_uri
            )
            is_streamed = True
        elif link_type == "cve2epss":
            target_files = task.get("object_files") or subject_files
            triples_count = _link_cve_to_epss_stream(
                out_file, target_files, predicate_uri
            )
            is_streamed = True
        elif link_type == "cwe2capec":
            triples_count = _link_cwe_to_capec(g, subject_files, predicate_uri)
        elif link_type == "capec2attck":
            triples_count = _link_capec_to_attck(g, subject_files, predicate_uri)
        elif link_type == "icsa2cve":
            triples_count = _link_icsa_to_cve(g, subject_files, predicate_uri)
        elif link_type == "d3fend2attck":
            triples_count = _link_d3fend_to_attck(g, subject_files, predicate_uri)
        elif link_type in ATTCK_RELATIONSHIP_LINKS:
            triples_count = _link_attck_relationships(
                out_file, subject_files, predicate_uri, *ATTCK_RELATIONSHIP_LINKS[link_type]
            )
            is_streamed = True
        elif link_type == "twin2attck":
            triples_count = _link_enterprise_twins(out_file, subject_files, predicate_uri)
            is_streamed = True
        elif link_type == "cve2attck":
            triples_count = _link_cve_to_attck_stream(
                out_file, subject_files, predicate_uri
            )
            is_streamed = True
        elif link_type == "cve2d3fend":
            triples_count = _link_cve_to_d3fend_stream(out_file, predicate_uri)
            is_streamed = True
        else:
            print(f"[{link_type}] WARNING: Unknown linking type")

        if not is_streamed:
            g.serialize(destination=str(out_file), format="turtle")
        result["status"] = "success"
        result["triples_count"] = triples_count
        result["output_file"] = str(out_file)
        print(f"[{link_type}] Success: {triples_count:,} triples written -> {out_file}")
    except (OSError, ValueError, RuntimeError, KeyError, SyntaxError) as e:  # SyntaxError: rdflib BadSyntax
        error_msg = f"{e!s}\n{traceback.format_exc()}"
        print(f"[{link_type}] Error: {error_msg}")
        result["error"] = str(e)
    linked_results = state.get("linked_results", [])
    linked_results.append(result)
    link_plan = state.get("link_plan", [])
    next_task = link_plan.pop(0) if link_plan else {}
    return {
        "link_plan": link_plan,
        "current_task": next_task,
        "linked_results": linked_results,
    }


def _resolve_predicate(predicate_str: str) -> URIRef:
    if ":" in predicate_str:
        prefix, local = predicate_str.split(":", 1)
        if prefix in NAMESPACES:
            return URIRef(NAMESPACES[prefix] + local)
    return URIRef(predicate_str)


def _iter_json_data(file_path: str):
    p = Path(file_path)
    file_size_mb = p.stat().st_size / (1024 * 1024)
    if file_size_mb > 10.0:
        with open(p, "rb") as f:
            first = f.read(1)
            while first in b" \t\r\n":
                first = f.read(1)
            f.seek(0)
            if first == b"[":
                for item in ijson.items(f, "item"):
                    if isinstance(item, dict):
                        yield item
            elif first == b"{":
                for k in ("vulnerabilities", "products", "objects", "scores"):
                    try:
                        f.seek(0)
                        gen = ijson.items(f, f"{k}.item")
                        first_item = next(gen)
                        if isinstance(first_item, dict):
                            yield first_item
                        for item in gen:
                            if isinstance(item, dict):
                                yield item
                        return
                    except (StopIteration, ijson.common.IncompleteJSONError):
                        continue
    else:
        with open(p, "rb") as f:
            data = orjson.loads(f.read())
        if isinstance(data, dict):
            for k in ("vulnerabilities", "products", "objects", "scores"):
                if k in data and isinstance(data[k], list):
                    yield from data[k]
                    return
            yield data
        elif isinstance(data, list):
            yield from data


def _load_json_data(file_path: str) -> dict | list:
    with open(file_path, "rb") as f:
        return orjson.loads(f.read())


def _strip_ns(tag: str) -> str:
    if "}" in tag:
        return tag.split("}", 1)[1]
    return tag


def _sanitize_uri_component(value: str) -> str:
    if not value:
        return value
    value = re.sub("<[^>]+>", "", value)
    value = re.sub("[\\x00-\\x1f]", "", value)
    value = re.sub("[\\s\"\\'{}<>|\\\\^`\\[\\]]", "_", value)
    return value


def _link_cve_to_cwe_stream(
    out_file: Path, subject_files: list[str], predicate: URIRef
) -> int:
    count = 0
    with open(out_file, "w", encoding="utf-8", buffering=2 * 1024 * 1024) as out_f:
        out_f.write("@prefix cve: <http://w3id.org/sepses/vocab/ref/cve#> .\n")
        out_f.write("@prefix cwe: <http://w3id.org/sepses/vocab/ref/cwe#> .\n")
        out_f.write("@prefix rdf: <http://www.w3.org/1999/02/22-rdf-syntax-ns#> .\n\n")

        for file_path in subject_files:
            for vuln in _iter_json_data(file_path):
                cve_data = vuln.get("cve", {})
                cve_id = cve_data.get("id")
                if not cve_id:
                    continue
                cve_id = _sanitize_uri_component(cve_id)
                subject_uri = RESOURCE_BASE["cve"] + cve_id

                cwe_refs = []
                for weakness in cve_data.get("weaknesses", []):
                    for desc in weakness.get("description", []):
                        cwe_value = desc.get("value", "")
                        if cwe_value.startswith("CWE-"):
                            cwe_refs.append(_sanitize_uri_component(cwe_value))

                if cwe_refs:
                    unique_cwes = list(dict.fromkeys(cwe_refs))
                    lines = [
                        f"<{predicate}> <{RESOURCE_BASE['cwe'] + cwe_val}>"
                        for cwe_val in unique_cwes
                    ]
                    count += len(unique_cwes)
                    out_f.write(f"<{subject_uri}> " + " ;\n    ".join(lines) + " .\n")
    return count


def _link_cve_to_cpe_stream(
    out_file: Path, subject_files: list[str], predicate: URIRef
) -> int:
    count = 0
    with open(out_file, "w", encoding="utf-8", buffering=2 * 1024 * 1024) as out_f:
        out_f.write("@prefix cve: <http://w3id.org/sepses/vocab/ref/cve#> .\n")
        out_f.write("@prefix cpe: <http://w3id.org/sepses/vocab/ref/cpe#> .\n")
        out_f.write("@prefix rdf: <http://www.w3.org/1999/02/22-rdf-syntax-ns#> .\n\n")

        for file_path in subject_files:
            for vuln in _iter_json_data(file_path):
                cve_data = vuln.get("cve", {})
                cve_id = cve_data.get("id")
                if not cve_id:
                    continue
                cve_id = _sanitize_uri_component(cve_id)
                subject_uri = RESOURCE_BASE["cve"] + cve_id

                cpe_uris = []
                for config in cve_data.get("configurations", []):
                    for node in config.get("nodes", []):
                        for cpe_match in node.get("cpeMatch", []):
                            cpe_uri_str = cpe_match.get("criteria", "")
                            if cpe_uri_str:
                                cpe_safe = cpe_uri_str.replace(":", "").replace("/", "")
                                cpe_safe = _sanitize_uri_component(cpe_safe)
                                cpe_uris.append(RESOURCE_BASE["cpe"] + cpe_safe)

                if cpe_uris:
                    unique_cpes = list(dict.fromkeys(cpe_uris))
                    lines = [f"<{predicate}> <{cu}>" for cu in unique_cpes]
                    count += len(unique_cpes)
                    out_f.write(f"<{subject_uri}> " + " ;\n    ".join(lines) + " .\n")
    return count


def _link_cve_to_epss_stream(
    out_file: Path, target_files: list[str], predicate: URIRef
) -> int:
    count = 0
    with open(out_file, "w", encoding="utf-8", buffering=2 * 1024 * 1024) as out_f:
        out_f.write("@prefix cve: <http://w3id.org/sepses/vocab/ref/cve#> .\n")
        out_f.write("@prefix epss: <http://w3id.org/sepses/vocab/ref/epss#> .\n")
        out_f.write("@prefix rdf: <http://www.w3.org/1999/02/22-rdf-syntax-ns#> .\n\n")

        for file_path in target_files:
            for rec in _iter_json_data(file_path):
                cve_id = rec.get("cve") or rec.get("cveID") or rec.get("id")
                if not cve_id:
                    continue
                cve_id = _sanitize_uri_component(cve_id)
                sub_uri = RESOURCE_BASE["cve"] + cve_id
                obj_uri = RESOURCE_BASE["epss"] + cve_id
                out_f.write(f"<{sub_uri}> <{predicate}> <{obj_uri}> .\n")
                count += 1
    return count


def _link_cwe_to_capec(g: Graph, subject_files: list[str], predicate: URIRef) -> int:
    count = 0
    for file_path in subject_files:
        try:
            if file_path.endswith(".xml"):
                count += _link_cwe_to_capec_xml(g, file_path, predicate)
        except (OSError, ValueError, RuntimeError, KeyError, ET.ParseError) as e:
            print(f"[Linking] Failed to process {file_path}: {e}")
            continue
    return count


def _link_cwe_to_capec_xml(g: Graph, file_path: str, predicate: URIRef) -> int:
    count = 0
    tree = ET.parse(file_path)
    root = tree.getroot()
    for elem in root.iter():
        tag = _strip_ns(elem.tag)
        if tag == "Weakness":
            cwe_id = elem.attrib.get("ID")
            if not cwe_id:
                continue
            subject_uri = URIRef(RESOURCE_BASE["cwe"] + f"CWE-{cwe_id}")
            for child in elem.iter():
                child_tag = _strip_ns(child.tag)
                if child_tag == "Related_Attack_Pattern":
                    capec_id = child.attrib.get("CAPEC_ID")
                    if capec_id:
                        object_uri = URIRef(
                            RESOURCE_BASE["capec"] + f"CAPEC-{capec_id}"
                        )
                        g.add((subject_uri, predicate, object_uri))
                        count += 1
    return count


def _link_capec_to_attck(g: Graph, subject_files: list[str], predicate: URIRef) -> int:
    count = 0
    for file_path in subject_files:
        try:
            if file_path.endswith(".xml"):
                count += _link_capec_to_attck_xml(g, file_path, predicate)
        except (OSError, ValueError, RuntimeError, KeyError, ET.ParseError) as e:
            print(f"[Linking] Failed to process {file_path}: {e}")
            continue
    return count


def _link_capec_to_attck_xml(g: Graph, file_path: str, predicate: URIRef) -> int:
    count = 0
    tree = ET.parse(file_path)
    root = tree.getroot()
    for elem in root.iter():
        tag = _strip_ns(elem.tag)
        if tag == "Attack_Pattern":
            capec_id = elem.attrib.get("ID")
            if not capec_id:
                continue
            subject_uri = URIRef(RESOURCE_BASE["capec"] + f"CAPEC-{capec_id}")
            for child in elem.iter():
                child_tag = _strip_ns(child.tag)
                if child_tag == "Taxonomy_Mapping":
                    taxonomy_name = child.attrib.get("Taxonomy_Name", "")
                    if "ATTACK" in taxonomy_name.upper():
                        for entry in child.iter():
                            entry_tag = _strip_ns(entry.tag)
                            if entry_tag == "Entry_ID" and entry.text:
                                technique_id = entry.text.strip()
                                if not technique_id.startswith("T"):
                                    technique_id = "T" + technique_id
                                object_uri = URIRef(
                                    RESOURCE_BASE["attck"] + technique_id
                                )
                                g.add((subject_uri, predicate, object_uri))
                                count += 1
    return count


def _link_icsa_to_cve(g: Graph, subject_files: list[str], predicate: URIRef) -> int:
    count = 0
    for file_path in subject_files:
        try:
            data = _load_json_data(file_path)
        except (OSError, ValueError, RuntimeError, KeyError) as e:
            print(f"[Linking] Failed to read {file_path}: {e}")
            continue
        vulnerabilities = []
        if isinstance(data, dict):
            vulnerabilities = data.get("vulnerabilities", [])
        elif isinstance(data, list):
            vulnerabilities = data
        for vuln in vulnerabilities:
            cve_id = vuln.get("cveID")
            if not cve_id:
                continue
            cve_id = _sanitize_uri_component(cve_id)
            vendor = _sanitize_uri_component(vuln.get("vendorProject", "unknown"))
            product = _sanitize_uri_component(vuln.get("product", "unknown"))
            icsa_id = f"{vendor}_{product}_{cve_id}".replace(" ", "_")
            subject_uri = URIRef(RESOURCE_BASE["icsa"] + icsa_id)
            object_uri = URIRef(RESOURCE_BASE["cve"] + cve_id)
            g.add((subject_uri, predicate, object_uri))
            count += 1
    return count


def _link_d3fend_to_attck(g: Graph, subject_files: list[str], predicate: URIRef) -> int:
    count = 0
    mappings_file = CACHE_DIR / "d3fend_mappings.json"
    if not mappings_file.exists():
        for sf in subject_files:
            if "d3fend_mappings" in sf:
                mappings_file = Path(sf)
                break
    if not mappings_file.exists():
        print("[Linking] d3fend_mappings.json not found in cache.")
        return 0
    try:
        data = _load_json_data(str(mappings_file))
        bindings = data.get("results", {}).get("bindings", [])
        for row in bindings:
            def_tech_val = row.get("def_tech", {}).get("value")
            off_tech_id = row.get("off_tech_id", {}).get("value")
            if not def_tech_val or not off_tech_id:
                continue
            def_uri = URIRef(def_tech_val)
            off_uri = URIRef(
                RESOURCE_BASE["attck"] + _sanitize_uri_component(off_tech_id)
            )
            g.add((def_uri, predicate, off_uri))
            count += 1
    except (OSError, ValueError, RuntimeError, KeyError) as e:
        print(f"[Linking] Failed to process {mappings_file}: {e}")
    return count


def _find_link_file(filename: str) -> Path | None:
    """Prefer this run's linking output; fall back to the last loaded copy."""
    for lookup_dir in (LINKING_OUTPUT_DIR, SPARQL_DATA_DIR):
        candidate = lookup_dir / filename
        if candidate.exists():
            return candidate
    return None


def _load_link_pairs(filename: str, predicate: URIRef) -> dict[str, set[str]]:
    """Parse a linking TTL file and return {subject local id: {object local id}}.

    Uses a real Turtle parser: rdflib serializes multi-object statements across
    several lines (``s p o1, o2 ;``), which line-based regexes silently miss.
    """
    pairs: dict[str, set[str]] = collections.defaultdict(set)
    link_file = _find_link_file(filename)
    if link_file is None:
        print(f"[Linking] WARNING: {filename} not found; dependent links will be incomplete.")
        return pairs
    g = Graph()
    g.parse(str(link_file), format="turtle")
    for s, o in g.subject_objects(predicate):
        pairs[_local_id(str(s))].add(_local_id(str(o)))
    return pairs


def _local_id(uri: str) -> str:
    return re.split(r"[/#]", uri)[-1]


def _build_cwe_to_attck_map() -> dict[str, set[str]]:
    cwe_to_capec = _load_link_pairs("cwe2capec.ttl", NS_CWE.hasCAPEC)
    capec_to_attck = _load_link_pairs("capec2attck.ttl", NS_CAPEC.hasRelatedAttackPattern)

    cwe_to_attck: dict[str, set[str]] = collections.defaultdict(set)
    for cwe, capecs in cwe_to_capec.items():
        for capec in capecs:
            cwe_to_attck[cwe].update(capec_to_attck.get(capec, ()))
    return cwe_to_attck


def _link_cve_to_attck_stream(
    out_file: Path, subject_files: list[str], predicate: URIRef
) -> int:
    count = 0
    cwe_to_attck = _build_cwe_to_attck_map()
    attck_regex = re.compile(
        r"attack\.mitre\.org/techniques/(T\d{4})(?:[/.](\d{3}))?", re.IGNORECASE
    )

    with open(out_file, "w", encoding="utf-8", buffering=2 * 1024 * 1024) as out_f:
        out_f.write("@prefix cve: <http://w3id.org/sepses/vocab/ref/cve#> .\n")
        out_f.write("@prefix attck: <http://w3id.org/sepses/resource/attack/> .\n\n")

        for file_path in subject_files:
            for vuln in _iter_json_data(file_path):
                cve_data = vuln.get("cve", {})
                cve_id = cve_data.get("id")
                if not cve_id:
                    continue
                cve_id = _sanitize_uri_component(cve_id)
                subject_uri = RESOURCE_BASE["cve"] + cve_id

                matched_attck: set[str] = set()

                for ref in cve_data.get("references", []):
                    url = ref.get("url", "")
                    m = attck_regex.search(url)
                    if m:
                        tech = m.group(1).upper()
                        matched_attck.add(f"{tech}.{m.group(2)}" if m.group(2) else tech)

                for weakness in cve_data.get("weaknesses", []):
                    for desc in weakness.get("description", []):
                        cwe_val = desc.get("value", "")
                        if cwe_val in cwe_to_attck:
                            matched_attck.update(cwe_to_attck[cwe_val])

                if matched_attck:
                    lines = [
                        f"<{predicate}> <{RESOURCE_BASE['attck'] + attck_id}>"
                        for attck_id in sorted(matched_attck)
                    ]
                    count += len(matched_attck)
                    out_f.write(f"<{subject_uri}> " + " ;\n    ".join(lines) + " .\n")
    return count


def _build_attck_to_d3fend_map() -> dict[str, set[str]]:
    d3fend_to_attck = _load_link_pairs("d3fend2attck.ttl", NS_D3FEND.counters)
    attck_to_d3fend: dict[str, set[str]] = collections.defaultdict(set)
    for def_id, techs in d3fend_to_attck.items():
        for tech in techs:
            attck_to_d3fend[tech].add(NAMESPACES["d3fend"] + def_id)
    return attck_to_d3fend


def _link_cve_to_d3fend_stream(out_file: Path, predicate: URIRef) -> int:
    count = 0
    attck_to_d3fend = _build_attck_to_d3fend_map()
    if not attck_to_d3fend:
        print("[Linking] No ATT&CK-to-D3FEND mappings found.")
        return 0

    cve_to_attck = _load_link_pairs("cve2attck.ttl", NS_CVE.relatedAttackPattern)
    if not cve_to_attck:
        print("[Linking] cve2attck.ttl not found or empty; cannot materialize D3FEND links.")
        return 0

    with open(out_file, "w", encoding="utf-8", buffering=2 * 1024 * 1024) as out_f:
        out_f.write("@prefix cve: <http://w3id.org/sepses/vocab/ref/cve#> .\n")
        out_f.write("@prefix d3fend: <http://d3fend.mitre.org/ontologies/d3fend.owl#> .\n\n")

        for cve_id in sorted(cve_to_attck):
            def_uris: set[str] = set()
            for tech_id in cve_to_attck[cve_id]:
                def_uris.update(attck_to_d3fend.get(tech_id, ()))
            if not def_uris:
                continue
            subject_uri = RESOURCE_BASE["cve"] + _sanitize_uri_component(cve_id)
            objects = ",\n        ".join(f"<{d_uri}>" for d_uri in sorted(def_uris))
            out_f.write(f"<{subject_uri}> <{predicate}> {objects} .\n")
            count += len(def_uris)
    return count


def _link_attck_relationships(
    out_file: Path,
    subject_files: list[str],
    predicate: URIRef,
    relationship_type: str,
    source_types: tuple[str, ...],
) -> int:
    """Write ATT&CK STIX relationships as triples between MITRE IDs, e.g.
    <attack/M1012> attck:mitigates <attack/T1461>. Ignores revoked/deprecated objects."""
    objects: dict[str, dict] = {}
    relationships: list[dict] = []
    for file_path in subject_files:
        for obj in _iter_json_data(file_path):
            if obj.get("revoked") or obj.get("x_mitre_deprecated"):
                continue
            if obj.get("type") == "relationship":
                if obj.get("relationship_type") == relationship_type:
                    relationships.append(obj)
            elif "id" in obj:
                objects[obj["id"]] = obj

    def mitre_id(obj: dict | None) -> str | None:
        for ref in (obj or {}).get("external_references", []):
            if ref.get("source_name") == "mitre-attack" and ref.get("external_id"):
                return _sanitize_uri_component(ref["external_id"])
        return None

    pairs: dict[str, set[str]] = collections.defaultdict(set)
    for rel in relationships:
        src, dst = objects.get(rel.get("source_ref")), objects.get(rel.get("target_ref"))
        if not src or not dst or src.get("type") not in source_types or dst.get("type") != "attack-pattern":
            continue
        s_id, t_id = mitre_id(src), mitre_id(dst)
        if s_id and t_id:
            pairs[s_id].add(t_id)

    count = 0
    with open(out_file, "w", encoding="utf-8", buffering=2 * 1024 * 1024) as out_f:
        out_f.write("@prefix attck: <http://w3id.org/sepses/vocab/ref/attack#> .\n\n")
        for s_id in sorted(pairs):
            objects_str = ",\n        ".join(f"<{RESOURCE_BASE['attck']}{t}>" for t in sorted(pairs[s_id]))
            out_f.write(f"<{RESOURCE_BASE['attck']}{s_id}> <{predicate}> {objects_str} .\n")
            count += len(pairs[s_id])
    return count


def _link_enterprise_twins(out_file: Path, subject_files: list[str], predicate: URIRef) -> int:
    """Link each Mobile/ICS technique to the Enterprise technique with the identical
    name (case-insensitive), e.g. mobile T1417.001 Keylogging -> T1056.001.

    Lets Mobile/ICS techniques reach D3FEND countermeasures, which are mapped to
    Enterprise techniques only. Exact names only: inheriting a parent's sub-technique
    links was rejected because it pulls in unrelated defences (e.g. network-flood
    controls for mobile passcode-reset denial of service).
    """
    def techniques(file_path: str) -> list[tuple[str, str]]:
        found = []
        for obj in _iter_json_data(file_path):
            if obj.get("type") != "attack-pattern" or obj.get("revoked") or obj.get("x_mitre_deprecated"):
                continue
            tid = next(
                (r.get("external_id") for r in obj.get("external_references", []) if r.get("source_name") == "mitre-attack"),
                None,
            )
            if tid and obj.get("name"):
                found.append((_sanitize_uri_component(tid), obj["name"].strip().lower()))
        return found

    enterprise_files = [f for f in subject_files if "enterprise" in Path(f).name]
    other_files = [f for f in subject_files if f not in enterprise_files]
    by_name: dict[str, set[str]] = collections.defaultdict(set)
    for f in enterprise_files:
        for tid, name in techniques(f):
            by_name[name].add(tid)

    pairs: dict[str, set[str]] = collections.defaultdict(set)
    for f in other_files:
        for tid, name in techniques(f):
            for twin in by_name.get(name, ()):
                if twin != tid:
                    pairs[tid].add(twin)

    count = 0
    with open(out_file, "w", encoding="utf-8", buffering=2 * 1024 * 1024) as out_f:
        out_f.write("@prefix attck: <http://w3id.org/sepses/vocab/ref/attack#> .\n\n")
        for tid in sorted(pairs):
            objects_str = ",\n        ".join(f"<{RESOURCE_BASE['attck']}{t}>" for t in sorted(pairs[tid]))
            out_f.write(f"<{RESOURCE_BASE['attck']}{tid}> <{predicate}> {objects_str} .\n")
            count += len(pairs[tid])
    return count
