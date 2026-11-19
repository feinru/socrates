from modules.validation.nodes import executor as vexec
from modules.validation.nodes.reviewer import reviewer


def _run(path, monkeypatch, tmp_path):
    monkeypatch.setattr("modules.validation.nodes.reviewer.VALIDATION_REPORTS_DIR", tmp_path / "reports")
    state = vexec.executor({"current_task": {"file_name": path.name, "file_path": str(path), "link_type": path.stem},
                            "validation_plan": [], "validation_results": []})
    return state["validation_results"][0]


def test_syntax_error_is_reported_not_raised(tmp_path, monkeypatch):
    bad = tmp_path / "cve2attck.ttl"
    bad.write_text("<http://e/s> <http://e/p> .\n")
    res = _run(bad, monkeypatch, tmp_path)
    assert res["status"] == "failed" and res["critical_errors_count"] == 1


def test_quality_score_uses_validated_triples(tmp_path, monkeypatch):
    monkeypatch.setattr("modules.validation.nodes.reviewer.VALIDATION_REPORTS_DIR", tmp_path / "reports")
    # Sampled big file: 10 of 10 validated triples are errors, but the full file
    # is estimated at 1M triples. The score must reflect the 100% error rate.
    results = [{"status": "success", "total_triples": 1_000_000, "validated_triples": 10,
                "validated_subjects": 10, "critical_errors_count": 0, "errors_count": 10, "warnings_count": 0}]
    reviewer({"validation_results": results})
    import json
    report = json.loads(next((tmp_path / "reports").glob("*.json")).read_text())
    assert report["compliance_score"] == 0.0
