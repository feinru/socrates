import logging
from typing import Dict, List, Optional
import chromadb
from chromadb.config import Settings

from modules.config import (
    CHROMA_DB_DIR,
    COLLECTION_SECURITY_ENTITIES,
    DEFAULT_CVE_INDEX_LIMIT,
    EMBEDDING_BATCH_SIZE,
)
from .extractor import (
    extract_attck_entities,
    extract_capec_entities,
    extract_cve_entities,
    extract_cwe_entities,
    extract_d3fend_entities,
)

logging.basicConfig(level=logging.WARNING, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger(__name__)


def get_chroma_client() -> chromadb.ClientAPI:
    return chromadb.PersistentClient(
        path=str(CHROMA_DB_DIR),
        settings=Settings(anonymized_telemetry=False, is_persistent=True),
    )


def get_or_create_collection(client: Optional[chromadb.ClientAPI] = None):
    c = client or get_chroma_client()
    return c.get_or_create_collection(
        name=COLLECTION_SECURITY_ENTITIES,
        metadata={"hnsw:space": "cosine"},
    )


def add_entities_batch(collection, batch: List[Dict[str, str]]):
    if not batch:
        return

    unique_items: Dict[str, Dict[str, str]] = {}
    for item in batch:
        uid = f"{item['type']}_{item['id']}"
        unique_items[uid] = item

    ids = list(unique_items.keys())
    documents = [unique_items[uid]["text"] for uid in ids]
    metadatas = [
        {
            "id": unique_items[uid].get("id", ""),
            "type": unique_items[uid].get("type", ""),
            "name": unique_items[uid].get("name", ""),
            "uri": unique_items[uid].get("uri", ""),
            "severity": unique_items[uid].get("severity", ""),
            "base_score": str(unique_items[uid].get("base_score", "")),
            "tactic": unique_items[uid].get("tactic", ""),
        }
        for uid in ids
    ]

    collection.upsert(ids=ids, documents=documents, metadatas=metadatas)


def build_vector_index(
    cve_limit: int = DEFAULT_CVE_INDEX_LIMIT,
    rebuild: bool = False,
) -> Dict[str, int]:
    client = get_chroma_client()

    if rebuild:
        try:
            client.delete_collection(COLLECTION_SECURITY_ENTITIES)
        except Exception:
            pass

    collection = get_or_create_collection(client)
    stats: Dict[str, int] = {}

    entity_sources = [
        ("cwe", extract_cwe_entities()),
        ("capec", extract_capec_entities()),
        ("attck", extract_attck_entities()),
        ("d3fend", extract_d3fend_entities()),
        ("cve", extract_cve_entities(limit=cve_limit)),
    ]

    print("[Vector] Indexing Process")
    for name, generator in entity_sources:
        batch: List[Dict[str, str]] = []
        count = 0

        for entity in generator:
            batch.append(entity)
            if len(batch) >= EMBEDDING_BATCH_SIZE:
                add_entities_batch(collection, batch)
                count += len(batch)
                batch = []

        if batch:
            add_entities_batch(collection, batch)
            count += len(batch)

        stats[name] = count
        icon = "[OK]" if count > 0 else "[FAIL]"
        print(f"{icon} {name.upper()}")
        print("   Status   : indexed")
        print(f"   Records  : {count:,}")

    total = sum(stats.values())
    print(f"Total       : {total:,} entities")
    return stats


if __name__ == "__main__":
    build_vector_index(cve_limit=DEFAULT_CVE_INDEX_LIMIT)
