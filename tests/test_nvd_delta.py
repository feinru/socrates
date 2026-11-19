"""Delta (incremental) NVD sync must never reuse pages from an older window and
must only advance the sync timestamp after every page has been merged."""

import json
from datetime import datetime, timedelta, timezone

import orjson
import pytest

import modules.fetcher.fetchers.nvd as nvd


class _Resp:
    def __init__(self, total):
        self._total = total

    def json(self):
        return {"totalResults": self._total}


class _Session:
    def __init__(self, total):
        self.total = total
        self.params = []

    def get(self, url, params=None, **kw):
        self.params.append(params)
        return _Resp(self.total)


def _cve(cve_id, desc):
    # Includes a float: ijson yields Decimal for it, which once crashed the merge.
    return {"cve": {"id": cve_id, "descriptions": [{"value": desc}],
                    "metrics": {"cvssMetricV31": [{"cvssData": {"baseScore": 7.5}}]}}}


@pytest.fixture
def env(tmp_path, monkeypatch):
    monkeypatch.setattr(nvd, "CACHE_DIR", tmp_path)
    monkeypatch.setattr("modules.fetcher.fetchers.base.CACHE_DIR", tmp_path)
    monkeypatch.setattr(nvd, "NVD_SYNC_FILE", tmp_path / "nvd_sync.json")
    monkeypatch.setattr(nvd, "MAX_DEMO", None)
    monkeypatch.setattr(nvd, "NVD_DELTA_DAYS", 0)
    base = [_cve("CVE-2024-0001", "old"), _cve("CVE-2024-0002", "unchanged")]
    (tmp_path / "cve.json").write_text(json.dumps(base))
    last = (datetime.now(timezone.utc) - timedelta(days=2)).isoformat()
    (tmp_path / "nvd_sync.json").write_text(json.dumps({"cve": last}))
    return tmp_path, last


def _install(monkeypatch, total, page_items, fail=False):
    session = _Session(total)
    monkeypatch.setattr(nvd, "_create_http_session", lambda pool_size: session)
    calls = []

    def worker(sess, url, src, key, start, size, rl, checkpoint_file, extra_params=None, max_retries=5):
        calls.append(dict(extra_params or {}))
        if fail:
            raise RuntimeError("simulated network failure")
        checkpoint_file.write_bytes(orjson.dumps(page_items))
        return len(page_items)

    monkeypatch.setattr(nvd, "_fetch_page_worker", worker)
    return session, calls


def _cache(tmp):
    return {c["cve"]["id"]: c["cve"]["descriptions"][0]["value"] for c in json.loads((tmp / "cve.json").read_text())}


def test_no_delta_without_base_snapshot(env):
    tmp, _ = env
    (tmp / "cve.json").unlink()
    assert nvd._get_delta_window("cve") is None


def test_stale_pages_from_previous_window_are_not_reused(env, monkeypatch):
    tmp, last = env
    stale_dir = tmp / ".cve_delta_pages"
    stale_dir.mkdir()
    (stale_dir / "page_00000000.json").write_bytes(orjson.dumps([_cve("CVE-2024-0001", "STALE")]))

    _, calls = _install(monkeypatch, total=1, page_items=[_cve("CVE-2024-0001", "new")])
    nvd._fetch_nvd_concurrent("http://nvd", "cve", "vulnerabilities")

    assert len(calls) == 1, "page must be fetched again, not served from the stale checkpoint"
    assert _cache(tmp) == {"CVE-2024-0001": "new", "CVE-2024-0002": "unchanged"}
    assert not stale_dir.exists()
    assert json.loads((tmp / "nvd_sync.json").read_text())["cve"] != last


def test_failed_pages_keep_timestamp_and_resume_same_window(env, monkeypatch):
    tmp, last = env
    _, calls = _install(monkeypatch, total=1, page_items=[], fail=True)
    with pytest.raises(RuntimeError, match="missing"):
        nvd._fetch_nvd_concurrent("http://nvd", "cve", "vulnerabilities")

    assert json.loads((tmp / "nvd_sync.json").read_text())["cve"] == last
    assert _cache(tmp)["CVE-2024-0001"] == "old"
    assert (tmp / ".cve_delta_pages" / "window.json").exists()
    first_window = calls[0]

    _, calls = _install(monkeypatch, total=1, page_items=[_cve("CVE-2024-0001", "new")])
    nvd._fetch_nvd_concurrent("http://nvd", "cve", "vulnerabilities")

    assert calls[0] == first_window, "the resumed run must query the original window"
    assert _cache(tmp)["CVE-2024-0001"] == "new"
    assert json.loads((tmp / "nvd_sync.json").read_text())["cve"] != last


def test_delta_ignores_demo_cap(env, monkeypatch):
    tmp, _ = env
    monkeypatch.setattr(nvd, "MAX_DEMO", 1)
    monkeypatch.setattr(nvd, "PAGE_SIZE", 1)
    _, calls = _install(monkeypatch, total=3, page_items=[_cve("CVE-2024-0009", "x")])
    nvd._fetch_nvd_concurrent("http://nvd", "cve", "vulnerabilities")
    assert len(calls) == 3


def test_failed_fetch_does_not_save_remote_version(env, monkeypatch):
    tmp, _ = env
    _install(monkeypatch, total=1, page_items=[], fail=True)
    fetcher = nvd.CVEFetcher()
    # BaseFetcher resolves version_file from its own CACHE_DIR import: redirect it
    # so the test never touches the real cache.
    monkeypatch.setattr(fetcher, "version_file", tmp / "cve.version")
    monkeypatch.setattr(fetcher, "get_remote_version", lambda: "999_new")
    (tmp / "cve.version").write_text("1_old")
    result = fetcher.run()
    assert result["status"] == "failed"
    assert (tmp / "cve.version").read_text() == "1_old", "version must stay stale so the next run resumes"
