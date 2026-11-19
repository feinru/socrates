from typing import Any, Dict, List, Optional
from .indexer import get_or_create_collection

_COLLECTION = None


def _get_collection():
    global _COLLECTION
    if _COLLECTION is None:
        _COLLECTION = get_or_create_collection()
    return _COLLECTION


def search_entities(
    query: str,
    entity_types: Optional[List[str]] = None,
    top_k: int = 5,
) -> List[Dict[str, Any]]:
    if not query or not query.strip():
        return []

    collection = _get_collection()

    where_filter = None
    if entity_types:
        cleaned_types = [t.lower().strip() for t in entity_types]
        if len(cleaned_types) == 1:
            where_filter = {"type": cleaned_types[0]}
        elif len(cleaned_types) > 1:
            where_filter = {"type": {"$in": cleaned_types}}

    results = collection.query(
        query_texts=[query.strip()],
        n_results=top_k,
        where=where_filter,
    )

    formatted: List[Dict[str, Any]] = []
    if not results or not results.get("ids") or not results["ids"][0]:
        return formatted

    ids = results["ids"][0]
    docs = results["documents"][0] if results.get("documents") else []
    metadatas = results["metadatas"][0] if results.get("metadatas") else []
    distances = results["distances"][0] if results.get("distances") else []

    for i, item_id in enumerate(ids):
        meta = metadatas[i] if i < len(metadatas) else {}
        doc = docs[i] if i < len(docs) else ""
        dist = distances[i] if i < len(distances) else 1.0
        similarity = round(max(0.0, 1.0 - dist), 4)

        formatted.append({
            "key": item_id,
            "id": meta.get("id", item_id),
            "type": meta.get("type", "unknown"),
            "name": meta.get("name", ""),
            "uri": meta.get("uri", ""),
            "similarity": similarity,
            "document": doc,
            "metadata": meta,
        })

    return formatted
