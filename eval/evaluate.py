"""Retrieval benchmark: pure vector vs. pure SPARQL vs. the production hybrid retriever.

Scoring rules (kept deliberately strict so the numbers mean something):

* IDs are compared exactly after normalisation (``CWE-7`` does not match ``CWE-79``,
  ``T1059`` does not match ``T1059.001``).
* ``hit_rate`` only counts expected entities that the question does *not* already
  name. Echoing an ID copied from the question is not retrieval. When every expected
  entity is named in the question (simple lookups), all of them are used instead.
* ``recall`` is the share of all expected entities retrieved.
* Negative controls (no expected entities) pass only when a method returns nothing
  *and* no error happened. A SPARQL failure always counts as a miss and is tallied
  under ``errors``.
* The hybrid column calls ``modules.vector.hybrid.retrieve_hybrid``, the same
  function behind the retriever service's ``/hybrid`` endpoint.

Caveat: ``NO_MATCH_SIMILARITY`` was tuned on this same dataset, so negative-control
scores are optimistic.
"""

import json
import logging
import os
import re
import sys
import time
from pathlib import Path
from typing import Any, Dict, List, Optional

import requests
from dotenv import load_dotenv

PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from modules.vector.hybrid import (  # noqa: E402
    ID_PATTERN,
    NO_MATCH_SIMILARITY,
    SparqlError,
    retrieve_hybrid,
)
from modules.vector.retriever import search_entities  # noqa: E402

load_dotenv()
logging.basicConfig(level=logging.WARNING, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger(__name__)

EVAL_DIR = Path(__file__).resolve().parent
BENCHMARK_FILE = EVAL_DIR / "dataset.json"
RESULTS_FILE = EVAL_DIR / "results.json"
SPARQL_ENDPOINT = os.getenv("SPARQL_ENDPOINT", "http://localhost:8890/sparql")
TOP_K = 5
METHODS = ("vector", "sparql", "hybrid")
_SPARQL_SESSION = requests.Session()


def _norm(entity_id: str) -> str:
    return entity_id.strip().upper()


def _ids_in(text: str) -> set:
    return {_norm(m) for m in re.findall(ID_PATTERN, text, re.IGNORECASE)}


def score(test_case: Dict[str, Any], retrieved_ids: List[str], error: Optional[str]) -> Dict[str, float]:
    expected = {_norm(e) for e in test_case.get("expected_entities", [])}
    retrieved = {_norm(r) for r in retrieved_ids if r}

    if error is not None:
        return {"hit_rate": 0.0, "recall": 0.0}

    if not expected:  # negative control: success means abstaining
        ok = 1.0 if not retrieved else 0.0
        return {"hit_rate": ok, "recall": ok}

    novel = expected - _ids_in(test_case["query"])
    targets = novel or expected
    return {
        "hit_rate": 1.0 if targets & retrieved else 0.0,
        "recall": len(expected & retrieved) / len(expected),
    }


def query_sparql(sparql_query: str) -> List[Dict[str, str]]:
    """Raise SparqlError on transport/HTTP failure so it is never scored as 'empty'."""
    try:
        resp = _SPARQL_SESSION.get(
            SPARQL_ENDPOINT,
            params={"query": sparql_query, "format": "application/sparql-results+json"},
            headers={"Accept": "application/sparql-results+json"},
            timeout=10,
        )
        resp.raise_for_status()
        data = resp.json()
    except (requests.RequestException, ValueError) as e:
        raise SparqlError(str(e)) from e
    return [{k: v.get("value", "") for k, v in row.items()} for row in data.get("results", {}).get("bindings", [])]


def _result(method: str, test_case: Dict[str, Any], ids: List[str], latency: float, error: Optional[str] = None):
    return {
        "method": method,
        **score(test_case, ids, error),
        "latency_sec": round(latency, 4),
        "retrieved_count": len(ids),
        "retrieved_ids": ids,
        "is_empty": len(ids) == 0,
        "error": error,
    }


def evaluate_pure_vector(test_case: Dict[str, Any]) -> Dict[str, Any]:
    start = time.perf_counter()
    results = search_entities(query=test_case["query"], top_k=TOP_K)
    # Same abstention rule as the hybrid retriever, so negative controls are comparable.
    if results and max(r["similarity"] for r in results) < NO_MATCH_SIMILARITY:
        results = []
    return _result("pure_vector", test_case, [r["id"] for r in results], time.perf_counter() - start)


def _sparql_lookup_query(query_text: str) -> str:
    ids_in_query = re.findall(ID_PATTERN, query_text, re.IGNORECASE)
    if ids_in_query:
        target_id = ids_in_query[0].upper()
        return f"""
        SELECT DISTINCT ?s ?id ?name ?desc WHERE {{
          {{ ?s <http://w3id.org/sepses/vocab/ref/cve#id> ?id . FILTER(str(?id) = "{target_id}") OPTIONAL {{ ?s <http://w3id.org/sepses/vocab/ref/cve#description> ?desc }} }}
          UNION
          {{ ?s <http://w3id.org/sepses/vocab/ref/cwe#id> ?id . FILTER(str(?id) = "{target_id}") OPTIONAL {{ ?s <http://w3id.org/sepses/vocab/ref/cwe#name> ?name ; <http://w3id.org/sepses/vocab/ref/cwe#description> ?desc }} }}
          UNION
          {{ ?s <http://w3id.org/sepses/vocab/ref/capec#id> ?id . FILTER(str(?id) = "{target_id}") OPTIONAL {{ ?s <http://w3id.org/sepses/vocab/ref/capec#name> ?name ; <http://w3id.org/sepses/vocab/ref/capec#description> ?desc }} }}
          UNION
          {{ ?s <http://w3id.org/sepses/vocab/ref/attack#techniqueId> ?id . FILTER(str(?id) = "{target_id}") OPTIONAL {{ ?s <http://w3id.org/sepses/vocab/ref/attack#name> ?name ; <http://w3id.org/sepses/vocab/ref/attack#description> ?desc }} }}
          UNION
          {{ ?s <http://d3fend.mitre.org/ontologies/d3fend.owl#d3fend-id> ?id . FILTER(str(?id) = "{target_id}") OPTIONAL {{ ?s <http://www.w3.org/2000/01/rdf-schema#label> ?name ; <http://d3fend.mitre.org/ontologies/d3fend.owl#definition> ?desc }} }}
        }} LIMIT 10
        """
    words = [w for w in re.findall(r"\w+", query_text) if len(w) > 3][:3]
    if not words:
        return "SELECT * WHERE { ?s ?p ?o } LIMIT 0"
    contains_expr = " AND ".join(f"'{w}'" for w in words)
    return f"""
    SELECT DISTINCT ?s ?id ?name ?desc WHERE {{
      {{ ?s <http://w3id.org/sepses/vocab/ref/cwe#description> ?desc . FILTER(bif:contains(?desc, "{contains_expr}")) OPTIONAL {{ ?s <http://w3id.org/sepses/vocab/ref/cwe#id> ?id ; <http://w3id.org/sepses/vocab/ref/cwe#name> ?name }} }}
      UNION
      {{ ?s <http://w3id.org/sepses/vocab/ref/attack#description> ?desc . FILTER(bif:contains(?desc, "{contains_expr}")) OPTIONAL {{ ?s <http://w3id.org/sepses/vocab/ref/attack#techniqueId> ?id ; <http://w3id.org/sepses/vocab/ref/attack#name> ?name }} }}
      UNION
      {{ ?s <http://w3id.org/sepses/vocab/ref/capec#description> ?desc . FILTER(bif:contains(?desc, "{contains_expr}")) OPTIONAL {{ ?s <http://w3id.org/sepses/vocab/ref/capec#id> ?id ; <http://w3id.org/sepses/vocab/ref/capec#name> ?name }} }}
      UNION
      {{ ?s <http://d3fend.mitre.org/ontologies/d3fend.owl#definition> ?desc . FILTER(bif:contains(?desc, "{contains_expr}")) OPTIONAL {{ ?s <http://d3fend.mitre.org/ontologies/d3fend.owl#d3fend-id> ?id ; <http://www.w3.org/2000/01/rdf-schema#label> ?name }} }}
    }} LIMIT 10
    """


def evaluate_pure_sparql(test_case: Dict[str, Any]) -> Dict[str, Any]:
    start = time.perf_counter()
    try:
        rows = query_sparql(_sparql_lookup_query(test_case["query"]))
        error = None
    except SparqlError as e:
        rows, error = [], str(e)
    ids = [r["id"] for r in rows if r.get("id")]
    return _result("pure_sparql", test_case, ids, time.perf_counter() - start, error)


def evaluate_hybrid(test_case: Dict[str, Any]) -> Dict[str, Any]:
    start = time.perf_counter()
    try:
        results = retrieve_hybrid(query=test_case["query"], top_k=TOP_K, endpoint=SPARQL_ENDPOINT)
        error = None
    except SparqlError as e:
        results, error = [], str(e)
    return _result("hybrid", test_case, [r["id"] for r in results], time.perf_counter() - start, error)


def _check_endpoint() -> bool:
    try:
        query_sparql("SELECT (1 AS ?x) WHERE { ?s ?p ?o } LIMIT 1")
        return True
    except SparqlError as e:
        print(f"[Evaluation] SPARQL endpoint {SPARQL_ENDPOINT} is unreachable: {e}")
        print("[Evaluation] Start Virtuoso (docker compose up -d virtuoso) and load the graph first.")
        return False


def _aggregate(rows: List[Dict[str, Any]]) -> Dict[str, Any]:
    n = len(rows)
    out: Dict[str, Any] = {"count": n}
    for m in METHODS:
        out[m] = {
            "hit_rate": round(100 * sum(r[m]["hit_rate"] for r in rows) / n, 1),
            "recall": round(100 * sum(r[m]["recall"] for r in rows) / n, 1),
            "avg_latency_sec": round(sum(r[m]["latency_sec"] for r in rows) / n, 4),
            "errors": sum(1 for r in rows if r[m]["error"]),
        }
    return out


def run_benchmark(limit: Optional[int] = None) -> None:
    if not BENCHMARK_FILE.exists():
        logger.error(f"Benchmark dataset not found at {BENCHMARK_FILE}")
        return
    if not _check_endpoint():
        sys.exit(1)

    with open(BENCHMARK_FILE, "r", encoding="utf-8") as f:
        dataset = json.load(f)
    if limit:
        dataset = dataset[:limit]

    print(f"[Evaluation] Running benchmark on {len(dataset)} test cases...")
    rows: List[Dict[str, Any]] = []
    for idx, tc in enumerate(dataset, 1):
        rows.append({
            "test_case": tc,
            "vector": evaluate_pure_vector(tc),
            "sparql": evaluate_pure_sparql(tc),
            "hybrid": evaluate_hybrid(tc),
        })
        if idx % 100 == 0 or idx == len(dataset):
            s = _aggregate(rows)
            print(
                f"[Evaluation] {idx}/{len(dataset)} "
                f"(hit: vector {s['vector']['hit_rate']}%, sparql {s['sparql']['hit_rate']}%, hybrid {s['hybrid']['hit_rate']}%)"
            )

    overall = _aggregate(rows)
    categories = sorted({r["test_case"]["category"] for r in rows})
    by_category = {c: _aggregate([r for r in rows if r["test_case"]["category"] == c]) for c in categories}

    print("\n[Evaluation] Final Results (hit rate / recall / avg latency / errors)")
    for label, stats in [("OVERALL", overall)] + [(c.upper(), by_category[c]) for c in categories]:
        print(f"{label} (n={stats['count']})")
        for m in METHODS:
            st = stats[m]
            print(
                f"   {m:<6}: {st['hit_rate']:5.1f}% / {st['recall']:5.1f}% / "
                f"{st['avg_latency_sec'] * 1000:6.1f}ms / {st['errors']} errors"
            )

    with open(RESULTS_FILE, "w", encoding="utf-8") as f:
        json.dump(
            {
                "summary": {
                    "total_test_cases": len(rows),
                    "top_k": TOP_K,
                    "no_match_similarity": NO_MATCH_SIMILARITY,
                    "overall": overall,
                    "by_category": by_category,
                },
                "details": rows,
            },
            f,
            indent=2,
        )
    print(f"\n[Evaluation] Results written to {RESULTS_FILE}")


if __name__ == "__main__":
    run_benchmark(int(sys.argv[1]) if len(sys.argv) > 1 else None)
