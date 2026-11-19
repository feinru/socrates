import importlib.util
from pathlib import Path

spec = importlib.util.spec_from_file_location("evaluate", Path(__file__).resolve().parent.parent / "eval" / "evaluate.py")
evaluate = importlib.util.module_from_spec(spec)
spec.loader.exec_module(evaluate)
score = evaluate.score


def tc(query, expected):
    return {"query": query, "expected_entities": expected}


def test_ids_match_exactly_not_as_substrings():
    assert score(tc("weakness for XSS", ["CWE-7"]), ["CWE-79"], None)["hit_rate"] == 0.0
    assert score(tc("technique", ["T1059"]), ["T1059.001"], None)["hit_rate"] == 0.0
    assert score(tc("weakness for XSS", ["cwe-79"]), ["CWE-79"], None)["hit_rate"] == 1.0


def test_echoing_the_query_id_is_not_a_hit():
    case = tc("Which technique relates to CVE-2007-5057?", ["CVE-2007-5057", "T1548"])
    assert score(case, ["CVE-2007-5057"], None) == {"hit_rate": 0.0, "recall": 0.5}
    assert score(case, ["CVE-2007-5057", "T1548"], None) == {"hit_rate": 1.0, "recall": 1.0}


def test_plain_lookup_counts_the_named_entity():
    assert score(tc("Lookup CVE-1999-0334", ["CVE-1999-0334"]), ["CVE-1999-0334"], None)["hit_rate"] == 1.0


def test_negative_control_requires_no_results_and_no_error():
    neg = tc("Explain CVE-2035-48684", [])
    assert score(neg, [], None)["hit_rate"] == 1.0
    assert score(neg, ["CVE-2035-48684"], None)["hit_rate"] == 0.0
    assert score(neg, [], "connection refused")["hit_rate"] == 0.0
