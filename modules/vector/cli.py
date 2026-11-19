import argparse
import json
import sys
from .retriever import search_entities


def main():
    parser = argparse.ArgumentParser(description="Query the SOCrates ChromaDB vector index")
    parser.add_argument("--query", "-q", type=str, required=True, help="Search query or description")
    parser.add_argument(
        "--types",
        "-t",
        nargs="+",
        default=None,
        help="Optional entity type filters",
    )
    parser.add_argument("--top_k", "-k", type=int, default=5, help="Number of results to return")
    parser.add_argument("--pretty", action="store_true", help="Pretty-print JSON output")

    args = parser.parse_args()
    results = search_entities(query=args.query, entity_types=args.types, top_k=args.top_k)

    indent = 2 if args.pretty else None
    json.dump(results, sys.stdout, indent=indent)
    print()


if __name__ == "__main__":
    main()
