import os
import re
import requests
from typing import Any, Dict, List, Optional
from dotenv import load_dotenv

from .retriever import search_entities

load_dotenv()
DEFAULT_SPARQL_ENDPOINT = os.getenv("SPARQL_ENDPOINT", "http://localhost:8890/sparql")
_SESSION = requests.Session()

# Below this best vector similarity, a query with no entity IDs and no
# entity_types filter is treated as "no matching entity" and returns nothing.
# Tuned on eval/dataset.json.
NO_MATCH_SIMILARITY = 0.38

ID_PATTERN = r"(CVE-\d{4}-\d+|CWE-\d+|T\d{4}(?:\.\d+)?|CAPEC-\d+|D3A?-[A-Z0-9.]+)"


class SparqlError(RuntimeError):
    """The SPARQL endpoint could not answer. Distinct from an empty result."""


def query_sparql(sparql_query: str, endpoint: Optional[str] = None) -> List[Dict[str, str]]:
    ep = endpoint or os.getenv("SPARQL_ENDPOINT", DEFAULT_SPARQL_ENDPOINT)
    try:
        resp = _SESSION.get(
            ep,
            params={"query": sparql_query, "format": "application/sparql-results+json"},
            headers={"Accept": "application/sparql-results+json"},
            timeout=10,
        )
        resp.raise_for_status()
        data = resp.json()
    except requests.HTTPError as e:
        raise SparqlError(f"SPARQL endpoint {ep} returned HTTP {e.response.status_code}") from e
    except requests.ConnectionError as e:
        raise SparqlError(f"SPARQL endpoint {ep} is unreachable") from e
    except requests.Timeout as e:
        raise SparqlError(f"SPARQL endpoint {ep} timed out") from e
    except (requests.RequestException, ValueError) as e:
        raise SparqlError(f"SPARQL endpoint {ep} failed ({type(e).__name__})") from e
    bindings = data.get("results", {}).get("bindings", [])
    return [{k: v.get("value", "") for k, v in row.items()} for row in bindings]


def get_graph_neighbors(target_id: str, endpoint: Optional[str] = None) -> List[str]:
    query = f"""
    SELECT DISTINCT ?id ?rel_id WHERE {{
      {{
        ?s <http://w3id.org/sepses/vocab/ref/cve#id> '{target_id}' .
        OPTIONAL {{
          {{ ?s <http://w3id.org/sepses/vocab/ref/cve#relatedAttackPattern> ?r . OPTIONAL {{ ?r <http://w3id.org/sepses/vocab/ref/attack#techniqueId> ?tid }} BIND(COALESCE(?tid, replace(str(?r), '^.*/', '')) AS ?rel_id) }}
          UNION
          {{ ?s <http://w3id.org/sepses/vocab/ref/cve#hasCountermeasure> ?r . OPTIONAL {{ ?r <http://d3fend.mitre.org/ontologies/d3fend.owl#d3fend-id> ?did }} BIND(COALESCE(?did, replace(str(?r), '^.*#', '')) AS ?rel_id) }}
          UNION
          {{ ?s <http://w3id.org/sepses/vocab/ref/cve#hasCWE> ?r . OPTIONAL {{ ?r <http://w3id.org/sepses/vocab/ref/cwe#id> ?wid }} BIND(COALESCE(?wid, replace(str(?r), '^.*/', '')) AS ?rel_id) }}
        }}
        BIND('{target_id}' AS ?id)
      }}
      UNION
      {{
        ?s <http://w3id.org/sepses/vocab/ref/cwe#id> '{target_id}' .
        OPTIONAL {{
          {{ ?s <http://w3id.org/sepses/vocab/ref/cwe#hasCAPEC> ?r . OPTIONAL {{ ?r <http://w3id.org/sepses/vocab/ref/capec#id> ?cid }} BIND(COALESCE(?cid, replace(str(?r), '^.*/', '')) AS ?rel_id) }}
        }}
        BIND('{target_id}' AS ?id)
      }}
      UNION
      {{
        ?s <http://w3id.org/sepses/vocab/ref/capec#id> '{target_id}' .
        OPTIONAL {{
          {{ ?s <http://w3id.org/sepses/vocab/ref/capec#hasRelatedAttackPattern> ?r . OPTIONAL {{ ?r <http://w3id.org/sepses/vocab/ref/attack#techniqueId> ?tid }} BIND(COALESCE(?tid, replace(str(?r), '^.*/', '')) AS ?rel_id) }}
          UNION
          {{ ?cwe <http://w3id.org/sepses/vocab/ref/cwe#hasCAPEC> ?s . ?cwe <http://w3id.org/sepses/vocab/ref/cwe#id> ?wid . BIND(?wid AS ?rel_id) }}
        }}
        BIND('{target_id}' AS ?id)
      }}
      UNION
      {{
        ?s <http://w3id.org/sepses/vocab/ref/attack#techniqueId> '{target_id}' .
        OPTIONAL {{
          {{ ?cap <http://w3id.org/sepses/vocab/ref/capec#hasRelatedAttackPattern> ?s . ?cap <http://w3id.org/sepses/vocab/ref/capec#id> ?cid . BIND(?cid AS ?rel_id) }}
          UNION
          {{ ?def <http://d3fend.mitre.org/ontologies/d3fend.owl#counters> ?s . OPTIONAL {{ ?def <http://d3fend.mitre.org/ontologies/d3fend.owl#d3fend-id> ?did }} BIND(COALESCE(?did, replace(str(?def), '^.*#', '')) AS ?rel_id) }}
        }}
        BIND('{target_id}' AS ?id)
      }}
      UNION
      {{
        ?s <http://d3fend.mitre.org/ontologies/d3fend.owl#d3fend-id> '{target_id}' .
        OPTIONAL {{
          {{ ?s <http://d3fend.mitre.org/ontologies/d3fend.owl#counters> ?att . OPTIONAL {{ ?att <http://w3id.org/sepses/vocab/ref/attack#techniqueId> ?tid }} BIND(COALESCE(?tid, replace(str(?att), '^.*/', '')) AS ?rel_id) }}
        }}
        BIND('{target_id}' AS ?id)
      }}
    }} LIMIT 25
    """
    rows = query_sparql(query, endpoint=endpoint)
    found_ids = set()
    for row in rows:
        if row.get("id"):
            found_ids.add(row["id"])
        if row.get("rel_id"):
            found_ids.add(row["rel_id"])
    return list(found_ids)


def retrieve_hybrid(
    query: str,
    top_k: int = 5,
    endpoint: Optional[str] = None,
    entity_types: Optional[List[str]] = None,
) -> List[Dict[str, Any]]:
    ids_in_query = re.findall(ID_PATTERN, query, re.IGNORECASE)

    graph_ids = []
    if ids_in_query:
        for qid in ids_in_query:
            graph_ids.extend(get_graph_neighbors(qid.upper(), endpoint=endpoint))

        if not graph_ids:
            return []

    vec_results = search_entities(query=query, entity_types=entity_types, top_k=top_k)

    # Abstain on weak matches only for open-ended searches (e.g. made-up entities).
    # With an entity_types filter the caller asked for the closest entities of that
    # type, whose texts (e.g. D3FEND definitions) score lower against attack phrasing.
    if not ids_in_query and not entity_types and vec_results:
        max_sim = max([r["similarity"] for r in vec_results])
        if max_sim < NO_MATCH_SIMILARITY:
            return []

    scored_ids: Dict[str, float] = {}
    meta_map: Dict[str, Dict[str, Any]] = {}
    q_lower = query.lower()

    for vr in vec_results:
        rid = vr["id"]
        meta_map[rid] = vr

    for gid in graph_ids:
        score = 1.0
        if any(gid.lower() == qid.lower() for qid in ids_in_query):
            score += 10.0
        elif (gid.startswith("T1") or gid.startswith("T0")) and any(w in q_lower for w in ["technique", "attack", "tactic"]):
            score += 5.0
        elif (gid.startswith("D3-") or gid.startswith("D3A-")) and any(w in q_lower for w in ["countermeasure", "mitigat", "defen", "d3fend"]):
            score += 5.0
        elif gid.startswith("CAPEC-") and any(w in q_lower for w in ["pattern", "capec", "exploit"]):
            score += 5.0
        elif gid.startswith("CWE-") and any(w in q_lower for w in ["weakness", "cwe"]):
            score += 5.0
        scored_ids[gid] = scored_ids.get(gid, 0.0) + score

    for rank, vr in enumerate(vec_results):
        rid = vr["id"]
        scored_ids[rid] = scored_ids.get(rid, 0.0) + (1.0 / (60.0 + rank)) * vr["similarity"]

    sorted_candidates = sorted(scored_ids.items(), key=lambda x: x[1], reverse=True)

    results: List[Dict[str, Any]] = []
    for item_id, score in sorted_candidates[:top_k]:
        meta = meta_map.get(item_id, {})
        itype = meta.get("type", "")
        if not itype:
            if item_id.startswith("CVE-"):
                itype = "cve"
            elif item_id.startswith("CWE-"):
                itype = "cwe"
            elif item_id.startswith("CAPEC-"):
                itype = "capec"
            elif item_id.startswith("T1") or item_id.startswith("T0"):
                itype = "attck"
            elif item_id.startswith("D3"):
                itype = "d3fend"
            else:
                itype = "entity"

        neighbors = [g for g in graph_ids if g != item_id]
        results.append({
            "id": item_id,
            "type": itype,
            "name": meta.get("name", item_id),
            "score": round(score, 3),
            "similarity": meta.get("similarity", 0.0),
            "uri": meta.get("uri", ""),
            "description": meta.get("document", ""),
            "graph_neighbors": neighbors[:5],
        })

    return results
