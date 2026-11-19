import sys
from pathlib import Path

if __name__ == "__main__" and __package__ is None:
    current_file_path = Path(__file__).resolve()
    parent_dir = current_file_path.parent.parent.parent
    if str(parent_dir) not in sys.path:
        sys.path.insert(0, str(parent_dir))
    from modules.vector.indexer import build_vector_index
else:
    from .indexer import build_vector_index


def run_vector():
    # Rebuild: upserts never remove entries that should no longer be indexed.
    build_vector_index(rebuild=True)


if __name__ == "__main__":
    run_vector()
