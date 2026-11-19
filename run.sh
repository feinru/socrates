#!/bin/bash
set -e

VIRTUOSO_HOST="${VIRTUOSO_HOST:-localhost}"

if [ -f ".venv/bin/python" ] && [ -z "$PYTHON" ]; then
  PYTHON=".venv/bin/python"
else
  PYTHON="${PYTHON:-python3}"
fi

STEP="${1:-all}"

run_fetch() {
  $PYTHON modules/fetcher/main.py
}

run_parse() {
  $PYTHON modules/parser/main.py
}

run_link() {
  $PYTHON modules/linking/main.py
}

run_validate() {
  $PYTHON modules/validation/main.py
}

run_load() {
  mkdir -p sparql/data sparql/data/ontology
  cp -u ontology/*.ttl sparql/data/ontology/ 2>/dev/null || cp ontology/*.ttl sparql/data/ontology/
  cp -u modules/parser/output/*.ttl sparql/data/ 2>/dev/null || cp modules/parser/output/*.ttl sparql/data/
  cp -u modules/linking/output/*.ttl sparql/data/ 2>/dev/null || cp modules/linking/output/*.ttl sparql/data/

  if ! curl -s -f "http://${VIRTUOSO_HOST}:8890/sparql" > /dev/null; then
    echo ""
    echo "[SPARQL] Waiting for Virtuoso on ${VIRTUOSO_HOST}:8890..."
    until curl -s -f "http://${VIRTUOSO_HOST}:8890/sparql" > /dev/null; do
      sleep 2
    done
    sleep 3
  fi

  $PYTHON modules/loader/main.py
}

run_vector() {
  $PYTHON modules/vector/main.py
}

run_eval() {
  $PYTHON eval/evaluate.py
}

run_test() {
  $PYTHON -m pytest tests -q
}

case "$STEP" in
  fetch)
    run_fetch
    ;;
  parse)
    run_parse
    ;;
  link)
    run_link
    ;;
  validate|validation)
    run_validate
    ;;
  load)
    run_load
    ;;
  vector|index)
    run_vector
    ;;
  eval)
    run_eval
    ;;
  test)
    run_test
    ;;
  all)
    run_fetch
    run_parse
    run_link
    run_validate
    run_load
    run_vector
    ;;
  *)
    echo "Unknown step: $STEP"
    echo "Usage: ./run.sh [all|fetch|parse|link|validate|load|vector|eval|test]"
    exit 1
    ;;
esac

echo ""
echo "Done successfully!"
