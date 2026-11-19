import json
import re
from pathlib import Path
from typing import Dict, Iterator, List, Optional, Set

from modules.config import PARSER_OUTPUT_DIR

# A Turtle string literal as written by the parser (json.dumps): handles \" escapes.
_LITERAL = r'"((?:\\.|[^"\\])*)"'


def _literal(block: str, pred_uri: str) -> Optional[str]:
    m = re.search(rf"<{re.escape(pred_uri)}>\s+{_LITERAL}", block)
    if not m:
        return None
    try:
        return json.loads(f'"{m.group(1)}"')
    except ValueError:
        return m.group(1)


def _literals(block: str, pred_uri: str) -> List[str]:
    return [json.loads(f'"{v}"') for v in re.findall(rf"<{re.escape(pred_uri)}>\s+{_LITERAL}", block)]


def extract_cwe_entities(file_path: Optional[Path] = None) -> Iterator[Dict[str, str]]:
    path = file_path or (PARSER_OUTPUT_DIR / "cwe.ttl")
    if not path.exists():
        return

    seen_ids = set()
    with open(path, "r", encoding="utf-8") as f:
        content = f.read()

    blocks = content.split(" a <http://w3id.org/sepses/vocab/ref/cwe#CWE>")
    for i in range(1, len(blocks)):
        prev_part = blocks[i - 1].strip().split()
        uri = prev_part[-1].strip("<>") if prev_part else ""
        block = blocks[i]

        cwe_id = _literal(block, "http://w3id.org/sepses/vocab/ref/cwe#id")
        if not cwe_id or cwe_id in seen_ids:
            continue
        seen_ids.add(cwe_id)

        name = _literal(block, "http://w3id.org/sepses/vocab/ref/cwe#name") or ""
        desc = (_literal(block, "http://w3id.org/sepses/vocab/ref/cwe#description") or "").strip()

        doc_text = f"[ID: {cwe_id}] [TYPE: CWE] [NAME: {name}] {cwe_id} {name}. Weakness Description: {desc}"
        yield {
            "id": cwe_id,
            "type": "cwe",
            "name": name,
            "description": desc[:1000],
            "uri": uri,
            "text": doc_text,
        }


def extract_capec_entities(file_path: Optional[Path] = None) -> Iterator[Dict[str, str]]:
    path = file_path or (PARSER_OUTPUT_DIR / "capec.ttl")
    if not path.exists():
        return

    seen_ids = set()
    with open(path, "r", encoding="utf-8") as f:
        content = f.read()

    blocks = content.split(" a <http://w3id.org/sepses/vocab/ref/capec#CAPEC>")
    for i in range(1, len(blocks)):
        prev_part = blocks[i - 1].strip().split()
        uri = prev_part[-1].strip("<>") if prev_part else ""
        block = blocks[i]

        capec_id = _literal(block, "http://w3id.org/sepses/vocab/ref/capec#id")
        if not capec_id or capec_id in seen_ids:
            continue
        seen_ids.add(capec_id)

        name = _literal(block, "http://w3id.org/sepses/vocab/ref/capec#name") or ""
        desc = (_literal(block, "http://w3id.org/sepses/vocab/ref/capec#description") or "").strip()

        doc_text = f"[ID: {capec_id}] [TYPE: CAPEC] [NAME: {name}] {capec_id} {name}. Attack Pattern Details: {desc}"
        yield {
            "id": capec_id,
            "type": "capec",
            "name": name,
            "description": desc[:1000],
            "uri": uri,
            "text": doc_text,
        }


def extract_attck_entities(files: Optional[List[Path]] = None) -> Iterator[Dict[str, str]]:
    target_files = files or [
        PARSER_OUTPUT_DIR / "attck_enterprise.ttl",
        PARSER_OUTPUT_DIR / "attck_ics.ttl",
        PARSER_OUTPUT_DIR / "attck_mobile.ttl",
    ]

    seen_ids = set()
    for path in target_files:
        if not path.exists():
            continue
        with open(path, "r", encoding="utf-8") as f:
            content = f.read()

        blocks = content.split(" a <http://w3id.org/sepses/vocab/ref/attack#AttackPattern>")
        for i in range(1, len(blocks)):
            prev_part = blocks[i - 1].strip().split()
            uri = prev_part[-1].strip("<>") if prev_part else ""
            block = blocks[i]

            tech_id = _literal(block, "http://w3id.org/sepses/vocab/ref/attack#techniqueId")
            if not tech_id or tech_id in seen_ids:
                continue
            seen_ids.add(tech_id)

            name = _literal(block, "http://w3id.org/sepses/vocab/ref/attack#name") or ""
            desc = " ".join((_literal(block, "http://w3id.org/sepses/vocab/ref/attack#description") or "").split())
            tactics = _literals(block, "http://w3id.org/sepses/vocab/ref/attack#tactic")
            tactic_str = ", ".join(tactics) if tactics else "unknown"

            doc_text = f"[ID: {tech_id}] [TYPE: ATT&CK] [NAME: {name}] [TACTIC: {tactic_str}] {tech_id} {name}. Technique Details: {desc[:800]}"
            yield {
                "id": tech_id,
                "type": "attck",
                "name": name,
                "description": desc[:1000],
                "tactic": tactic_str,
                "uri": uri,
                "text": doc_text,
            }


def extract_d3fend_entities(file_path: Optional[Path] = None) -> Iterator[Dict[str, str]]:
    path = file_path or (PARSER_OUTPUT_DIR / "d3fend.ttl")
    if not path.exists():
        return

    seen_ids = set()
    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        content = f.read()

    pattern = re.compile(
        r"(?m)^(?:d3fend:([A-Za-z0-9_.-]+)|<http://d3fend\.mitre\.org/ontologies/d3fend\.owl#([A-Za-z0-9_.-]+)>)\s+a\s+"
    )
    matches = list(pattern.finditer(content))

    for i, m in enumerate(matches):
        subj = m.group(1) or m.group(2)
        start = m.start()
        end = matches[i + 1].start() if i + 1 < len(matches) else len(content)
        block = content[start:end]

        id_m = re.search(r'd3fend:d3fend-id\s+"([^"]+)"', block)
        if not id_m:
            continue

        d3_id = id_m.group(1)
        if d3_id in seen_ids:
            continue
        seen_ids.add(d3_id)

        label_m = re.search(
            r'rdfs:label\s+(?:"""(.*?)"""|"((?:\\.|[^"\\])*)")', block, re.DOTALL
        )
        label = (label_m.group(1) or label_m.group(2) or "").strip() if label_m else subj

        def_m = re.search(
            r'd3fend:definition\s+(?:"""(.*?)"""|"((?:\\.|[^"\\])*)")', block, re.DOTALL
        )
        if not def_m:
            def_m = re.search(
                r'd3fend:d3fend-annotation\s+(?:"""(.*?)"""|"((?:\\.|[^"\\])*)")',
                block,
                re.DOTALL,
            )
        if not def_m:
            def_m = re.search(
                r'rdfs:comment\s+(?:"""(.*?)"""|"((?:\\.|[^"\\])*)")', block, re.DOTALL
            )

        definition = (
            (def_m.group(1) or def_m.group(2) or "").replace("\n", " ").strip()
            if def_m
            else ""
        )

        # D3- IDs are defensive techniques; D3A- IDs are analytic methods (ML,
        # statistics) that D3FEND references, not countermeasures.
        kind = "Analytic Method Details" if d3_id.startswith("D3A-") else "Defensive Mitigation Details"
        doc_text = f"[ID: {d3_id}] [TYPE: D3FEND] [NAME: {label}] {d3_id} {label}. {kind}: {definition}"
        yield {
            "id": d3_id,
            "type": "d3fend",
            "name": label,
            "description": definition[:1000],
            "uri": f"http://d3fend.mitre.org/ontologies/d3fend.owl#{subj}",
            "text": doc_text,
        }


def _kev_cve_ids() -> Set[str]:
    path = PARSER_OUTPUT_DIR / "icsa.ttl"
    if not path.exists():
        return set()
    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        return set(re.findall(r'icsa#cveID>\s+"(CVE-\d+-\d+)"', f.read()))


def _iter_cve_records(path: Path) -> Iterator[Dict[str, str]]:
    """Yield one dict per CVE statement in the parser's cve.ttl."""
    record: Dict[str, str] = {}
    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            line_str = line.strip()
            if line_str.startswith("<http://w3id.org/sepses/resource/cve/CVE-"):
                record = {"uri": line_str.split()[0].strip("<>")}
            for key, pred in (
                ("id", "cve#id"),
                ("description", "cve#description"),
                ("base_score", "cve#baseScore"),
                ("severity", "cve#severity"),
                ("published", "cve#published"),
            ):
                if f"{pred}>" in line_str:
                    val = _literal(line_str, f"http://w3id.org/sepses/vocab/ref/{pred}")
                    if val is not None:
                        record[key] = val
            if line_str.endswith(".") and "id" in record:
                yield record
                record = {}


def select_cve_ids(path: Path, limit: Optional[int]) -> Optional[Set[str]]:
    """Pick which CVEs to embed when capped: known-exploited (KEV) first, then the
    most recently published. File order is oldest-first, so a plain prefix would
    only ever index 1999-2004 CVEs."""
    if not limit:
        return None
    kev = _kev_cve_ids()
    dated = [(r.get("published", ""), r["id"]) for r in _iter_cve_records(path)]
    ranked = sorted(dated, key=lambda x: (x[1] in kev, x[0]), reverse=True)
    return {cve_id for _, cve_id in ranked[:limit]}


def extract_cve_entities(file_path: Optional[Path] = None, limit: Optional[int] = None) -> Iterator[Dict[str, str]]:
    path = file_path or (PARSER_OUTPUT_DIR / "cve.ttl")
    if not path.exists():
        return

    selected = select_cve_ids(path, limit)
    for rec in _iter_cve_records(path):
        cve_id = rec["id"]
        if selected is not None and cve_id not in selected:
            continue
        desc = rec.get("description", "")
        sev = rec.get("severity", "UNKNOWN")
        score = rec.get("base_score", "N/A")
        yield {
            "id": cve_id,
            "type": "cve",
            "name": cve_id,
            "uri": rec["uri"],
            "severity": rec.get("severity", ""),
            "base_score": rec.get("base_score", ""),
            "description": desc,
            "text": f"[ID: {cve_id}] [TYPE: CVE] {cve_id} [Severity: {sev}, CVSS: {score}]. Vulnerability Details: {desc}",
        }
