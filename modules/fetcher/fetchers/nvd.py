from __future__ import annotations

import collections
from datetime import datetime, timedelta, timezone
import json
import os
import shutil
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Any

import ijson
import orjson
import requests
from requests.adapters import HTTPAdapter
from urllib3.util import Retry

from modules.config import (
    CACHE_DIR,
    NVD_API_KEY,
    NVD_CPE_URL,
    NVD_CVE_URL,
    NVD_DELTA_DAYS,
    NVD_SYNC_FILE,
)
from modules.config import (
    NVD_MAX_DEMO as MAX_DEMO,
)
from modules.config import (
    NVD_PAGE_SIZE as PAGE_SIZE,
)

from .base import BaseFetcher


class SlidingWindowRateLimiter:
    def __init__(self, max_calls: int, period_seconds: float) -> None:
        self.max_calls = max_calls
        self.period_seconds = period_seconds
        self.timestamps: collections.deque[float] = collections.deque()
        self.lock = threading.Lock()

    def acquire(self) -> None:
        while True:
            with self.lock:
                now = time.monotonic()
                while (
                    self.timestamps
                    and (now - self.timestamps[0]) >= self.period_seconds
                ):
                    self.timestamps.popleft()

                if len(self.timestamps) < self.max_calls:
                    self.timestamps.append(now)
                    return

                wait_time = self.period_seconds - (now - self.timestamps[0]) + 0.05
            time.sleep(max(0.02, wait_time))


def _get_headers() -> dict[str, str]:
    if NVD_API_KEY:
        return {"apiKey": NVD_API_KEY}
    return {}


def _create_http_session(pool_size: int) -> requests.Session:
    session = requests.Session()
    retries = Retry(
        total=3,
        backoff_factor=1.0,
        status_forcelist=[500, 502, 503, 504],
        raise_on_status=False,
    )
    adapter = HTTPAdapter(
        pool_connections=pool_size,
        pool_maxsize=pool_size,
        max_retries=retries,
    )
    session.mount("https://", adapter)
    session.mount("http://", adapter)
    return session


def _fetch_page_worker(
    session: requests.Session,
    base_url: str,
    source_name: str,
    item_key: str,
    start_index: int,
    batch_size: int,
    rate_limiter: SlidingWindowRateLimiter,
    checkpoint_file: Path,
    extra_params: dict[str, str] | None = None,
    max_retries: int = 5,
) -> int:
    if checkpoint_file.exists() and checkpoint_file.stat().st_size > 10:
        return 0

    headers = _get_headers()
    params: dict[str, Any] = {"resultsPerPage": batch_size, "startIndex": start_index}
    if extra_params:
        params.update(extra_params)

    for attempt in range(max_retries):
        rate_limiter.acquire()
        t0 = time.monotonic()
        try:
            resp = session.get(base_url, params=params, headers=headers, timeout=90)
            elapsed = time.monotonic() - t0

            if resp.status_code == 200:
                body = resp.json()
                items: list[dict[str, Any]] = body.get(item_key, [])

                tmp_file = checkpoint_file.with_suffix(".tmp")
                with open(tmp_file, "wb") as f:
                    f.write(orjson.dumps(items))
                tmp_file.replace(checkpoint_file)

                return len(items)

            if resp.status_code in (403, 429, 503):
                backoff = min(60.0, (2**attempt) * 5.0)
                print(
                    f"[{source_name}] Rate/load limited ({resp.status_code}) on index {start_index}. "
                    f"Backing off {backoff:.1f}s (attempt {attempt + 1}/{max_retries})..."
                )
                time.sleep(backoff)
            else:
                print(
                    f"[{source_name}] HTTP {resp.status_code} on index {start_index}: {resp.text[:150]}"
                )
                time.sleep(3.0)

        except requests.RequestException as exc:
            elapsed = time.monotonic() - t0
            backoff = min(30.0, (attempt + 1) * 4.0)
            print(
                f"[{source_name}] Network error on index {start_index} after {elapsed:.1f}s: {exc}. "
                f"Retrying in {backoff:.1f}s..."
            )
            time.sleep(backoff)

    print(
        f"[{source_name}] Failed to fetch page starting at {start_index} after {max_retries} attempts."
    )
    return 0


def _get_delta_window(source_name: str) -> tuple[str, str] | None:
    # Without a base snapshot there is nothing to merge a delta into.
    if not (CACHE_DIR / f"{source_name}.json").exists():
        return None
    now = datetime.now(timezone.utc)
    start_dt = None
    if NVD_SYNC_FILE.exists():
        try:
            with open(NVD_SYNC_FILE, "r", encoding="utf-8") as f:
                sync_data = json.load(f)
            last_sync_str = sync_data.get(source_name)
            if last_sync_str:
                start_dt = datetime.fromisoformat(last_sync_str)
        except (OSError, ValueError, json.JSONDecodeError):
            start_dt = None

    if start_dt is None and NVD_DELTA_DAYS > 0:
        start_dt = now - timedelta(days=NVD_DELTA_DAYS)

    if start_dt is None:
        return None

    if (now - start_dt).days > 120:
        start_dt = now - timedelta(days=120)

    start_str = start_dt.strftime("%Y-%m-%dT%H:%M:%S.000")
    end_str = now.strftime("%Y-%m-%dT%H:%M:%S.000")
    return (start_str, end_str)


def _record_sync_timestamp(source_name: str, timestamp_iso: str) -> None:
    sync_data = {}
    if NVD_SYNC_FILE.exists():
        try:
            with open(NVD_SYNC_FILE, "r", encoding="utf-8") as f:
                sync_data = json.load(f)
        except (OSError, ValueError, json.JSONDecodeError):
            sync_data = {}
    sync_data[source_name] = timestamp_iso
    tmp_file = NVD_SYNC_FILE.with_suffix(".tmp")
    with open(tmp_file, "w", encoding="utf-8") as f:
        json.dump(sync_data, f, indent=2)
    tmp_file.replace(NVD_SYNC_FILE)


def _get_item_key(item: dict[str, Any], item_key: str) -> str | None:
    if item_key == "vulnerabilities":
        return item.get("cve", {}).get("id")
    if item_key == "products":
        cpe = item.get("cpe", {})
        return cpe.get("cpeNameId") or cpe.get("cpe23Uri")
    return None


def _merge_delta_records(
    cache_file: Path,
    delta_map: dict[str, dict[str, Any]],
    item_key: str,
) -> int:
    tmp_cache = cache_file.with_suffix(".tmp")
    total_records = 0
    with open(tmp_cache, "w", encoding="utf-8", buffering=2 * 1024 * 1024) as out_f:
        out_f.write("[\n")
        first_item = True
        if cache_file.exists():
            with open(cache_file, "rb") as in_f:
                # use_float: ijson's default Decimal values are not orjson-serializable.
                for item in ijson.items(in_f, "item", use_float=True):
                    k = _get_item_key(item, item_key)
                    record_to_write = delta_map.pop(k, item) if k else item
                    if not first_item:
                        out_f.write(",\n")
                    out_f.write(orjson.dumps(record_to_write).decode("utf-8"))
                    first_item = False
                    total_records += 1

        for remaining_item in delta_map.values():
            if not first_item:
                out_f.write(",\n")
            out_f.write(orjson.dumps(remaining_item).decode("utf-8"))
            first_item = False
            total_records += 1
        out_f.write("\n]\n")
    tmp_cache.replace(cache_file)
    return total_records


def _fetch_nvd_concurrent(
    base_url: str,
    source_name: str,
    item_key: str,
) -> list[dict[str, Any]]:
    session = _create_http_session(pool_size=12)
    headers = _get_headers()

    delta_dir = CACHE_DIR / f".{source_name}_delta_pages"
    window_file = delta_dir / "window.json"
    delta_window: tuple[str, str] | None = None
    sync_ts = datetime.now(timezone.utc).isoformat()
    if window_file.exists():
        # Resume an interrupted delta run with its original window, so the
        # page checkpoints on disk still match the query being made.
        try:
            saved = json.loads(window_file.read_text(encoding="utf-8"))
            delta_window = (saved["start"], saved["end"])
            sync_ts = saved["sync_ts"]
            print(f"[{source_name}] Resuming interrupted delta sync.")
        except (OSError, ValueError, KeyError):
            shutil.rmtree(delta_dir, ignore_errors=True)
            delta_window = None
    if delta_window is None:
        delta_window = _get_delta_window(source_name)
        if delta_window:
            shutil.rmtree(delta_dir, ignore_errors=True)
            delta_dir.mkdir(parents=True, exist_ok=True)
            window_file.write_text(
                json.dumps({"start": delta_window[0], "end": delta_window[1], "sync_ts": sync_ts}),
                encoding="utf-8",
            )

    extra_params: dict[str, str] = {}
    if delta_window:
        extra_params["lastModStartDate"] = delta_window[0]
        extra_params["lastModEndDate"] = delta_window[1]
        print(f"[{source_name}] Delta sync active: {delta_window[0]} -> {delta_window[1]}")

    probe_params: dict[str, Any] = {"resultsPerPage": 1, "startIndex": 0}
    if extra_params:
        probe_params.update(extra_params)

    try:
        resp = session.get(
            base_url,
            params=probe_params,
            headers=headers,
            timeout=45,
        )
        total = resp.json().get("totalResults", 0)
    except (requests.RequestException, json.JSONDecodeError, KeyError) as e:
        print(f"[{source_name}] Error probing total results: {e}")
        return []

    if delta_window and total == 0:
        print(f"[{source_name}] No updated records in delta window.")
        _record_sync_timestamp(source_name, sync_ts)
        shutil.rmtree(delta_dir, ignore_errors=True)
        return []

    # A delta run must fetch every changed record, otherwise advancing the sync
    # timestamp would drop the rest permanently. The demo cap only applies to full runs.
    if delta_window or MAX_DEMO is None or MAX_DEMO <= 0:
        target_total = total
    else:
        target_total = min(MAX_DEMO, total)
    if target_total < total:
        print(
            f"[{source_name}] Capped mode: fetching first {target_total:,} of {total:,} records"
        )
    else:
        print(f"[{source_name}] Full dataset mode: fetching all {total:,} records")

    if NVD_API_KEY:
        max_workers = int(os.getenv("NVD_WORKERS", "6"))
        rate_limiter = SlidingWindowRateLimiter(max_calls=40, period_seconds=30.0)
    else:
        max_workers = 1
        rate_limiter = SlidingWindowRateLimiter(max_calls=4, period_seconds=30.0)

    checkpoint_dir = delta_dir if delta_window else CACHE_DIR / f".{source_name}_pages"
    checkpoint_dir.mkdir(parents=True, exist_ok=True)

    page_indices = list(range(0, target_total, PAGE_SIZE))
    total_pages = len(page_indices)

    completed_indices: set[int] = set()
    pending_indices: list[int] = []

    for idx in page_indices:
        chk_file = checkpoint_dir / f"page_{idx:08d}.json"
        if chk_file.exists() and chk_file.stat().st_size > 10:
            completed_indices.add(idx)
        else:
            pending_indices.append(idx)

    cached_count = len(completed_indices)
    if cached_count > 0:
        print(
            f"[{source_name}] Resuming from checkpoint: {cached_count}/{total_pages} pages already on disk."
        )

    if pending_indices:
        print(
            f"[{source_name}] Dispatching {len(pending_indices)} pending pages "
            f"across {max_workers} worker threads..."
        )

        worker_session = _create_http_session(pool_size=max_workers * 2)
        start_time = time.monotonic()

        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            future_to_idx = {
                executor.submit(
                    _fetch_page_worker,
                    worker_session,
                    base_url,
                    source_name,
                    item_key,
                    idx,
                    min(PAGE_SIZE, target_total - idx),
                    rate_limiter,
                    checkpoint_dir / f"page_{idx:08d}.json",
                    extra_params,
                ): idx
                for idx in pending_indices
            }

            for future in as_completed(future_to_idx):
                idx = future_to_idx[future]
                try:
                    num_items = future.result()
                    completed_indices.add(idx)
                    done_count = len(completed_indices)
                    pct = (done_count / total_pages) * 100.0
                    print(
                        f"[{source_name}] Progress: page {done_count}/{total_pages} "
                        f"({pct:.1f}%) | index {idx:,} saved {num_items:,} items"
                    )
                except (requests.RequestException, OSError, RuntimeError) as exc:
                    print(f"[{source_name}] Exception on page index {idx}: {exc}")

        total_elapsed = time.monotonic() - start_time
        print(
            f"[{source_name}] Completed fetching {len(pending_indices)} pages in {total_elapsed:.1f}s."
        )

    missing_pages = [
        idx
        for idx in page_indices
        if not (checkpoint_dir / f"page_{idx:08d}.json").exists()
    ]
    if missing_pages:
        print(
            f"[{source_name}] WARNING: {len(missing_pages)}/{total_pages} pages failed to download. "
            "The sync timestamp was not advanced; re-run the fetcher to resume."
        )

    cache_file = CACHE_DIR / f"{source_name}.json"
    if delta_window and cache_file.exists():
        if missing_pages:
            # Raise so BaseFetcher.run() does not record the remote version;
            # otherwise the next run thinks it is up to date and never resumes.
            raise RuntimeError(f"{len(missing_pages)} delta pages missing; re-run to resume")
        delta_map: dict[str, dict[str, Any]] = {}
        for idx in sorted(page_indices):
            chk_file = checkpoint_dir / f"page_{idx:08d}.json"
            if not chk_file.exists():
                continue
            with open(chk_file, "rb") as pf:
                page_data = orjson.loads(pf.read())
            if isinstance(page_data, list):
                for item in page_data:
                    k = _get_item_key(item, item_key)
                    if k:
                        delta_map[k] = item
        total_records = _merge_delta_records(cache_file, delta_map, item_key)
        _record_sync_timestamp(source_name, sync_ts)
        shutil.rmtree(delta_dir, ignore_errors=True)
        print(f"[{source_name}] Delta merged {len(delta_map):,} updates, total: {total_records:,} records -> {cache_file}")
        return []

    tmp_cache = cache_file.with_suffix(".tmp")
    total_records = 0
    print(f"[{source_name}] Stream assembling {total_pages} pages into {cache_file}...")
    with open(tmp_cache, "w", encoding="utf-8", buffering=2 * 1024 * 1024) as out_f:
        out_f.write("[\n")
        first_item = True
        for idx in sorted(page_indices):
            chk_file = checkpoint_dir / f"page_{idx:08d}.json"
            if not chk_file.exists():
                continue
            with open(chk_file, "rb") as pf:
                page_data = orjson.loads(pf.read())
            if isinstance(page_data, list):
                for item in page_data:
                    if not first_item:
                        out_f.write(",\n")
                    out_f.write(orjson.dumps(item).decode("utf-8"))
                    first_item = False
                    total_records += 1
        out_f.write("\n]\n")
    tmp_cache.replace(cache_file)
    if delta_window:
        shutil.rmtree(delta_dir, ignore_errors=True)
    if not missing_pages and target_total == total:
        # Only a complete, uncapped snapshot is a valid base for future delta syncs.
        _record_sync_timestamp(source_name, sync_ts)
    print(f"[{source_name}] Stream assembled {total_records:,} records -> {cache_file}")
    if missing_pages:
        raise RuntimeError(f"{len(missing_pages)} pages missing; cache is partial, re-run to resume")
    return []


class CVEFetcher(BaseFetcher):
    def __init__(self) -> None:
        super().__init__("cve")
        self.base_url = NVD_CVE_URL

    def get_remote_version(self) -> str | None:
        try:
            resp = requests.get(
                self.base_url,
                params={"resultsPerPage": 1},
                headers=_get_headers(),
                timeout=30,
            )
            data = resp.json()
            total = data.get("totalResults", 0)
            if data.get("vulnerabilities"):
                last_mod = data["vulnerabilities"][0]["cve"]["lastModified"]
                return f"{total}_{last_mod}"
        except (requests.RequestException, json.JSONDecodeError, KeyError) as e:
            print(f"[cve] Failed to check remote version: {e}")
        return None

    def fetch(self) -> list[dict[str, Any]]:
        return _fetch_nvd_concurrent(
            base_url=self.base_url,
            source_name="cve",
            item_key="vulnerabilities",
        )


class CPEFetcher(BaseFetcher):
    def __init__(self) -> None:
        super().__init__("cpe")
        self.base_url = NVD_CPE_URL

    def get_remote_version(self) -> str | None:
        try:
            resp = requests.get(
                self.base_url,
                params={"resultsPerPage": 1},
                headers=_get_headers(),
                timeout=30,
            )
            data = resp.json()
            total = data.get("totalResults", 0)
            if data.get("products"):
                last_mod = data["products"][0]["cpe"]["lastModified"]
                return f"{total}_{last_mod}"
        except (requests.RequestException, json.JSONDecodeError, KeyError) as e:
            print(f"[cpe] Failed to check remote version: {e}")
        return None

    def fetch(self) -> list[dict[str, Any]]:
        return _fetch_nvd_concurrent(
            base_url=self.base_url,
            source_name="cpe",
            item_key="products",
        )
