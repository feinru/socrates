import json
import logging
import os
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, Dict
import requests

from .hybrid import SparqlError, retrieve_hybrid
from .retriever import search_entities

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger(__name__)

PORT = int(os.getenv("PORT", "8000"))
HOST = os.getenv("HOST", "0.0.0.0")
SPARQL_ENDPOINT = os.getenv("SPARQL_ENDPOINT", "http://localhost:8890/sparql")
# Clients used to hit Virtuoso directly with no timeout; keep heavy analytical
# queries working through the proxy.
SPARQL_PROXY_TIMEOUT = float(os.getenv("SPARQL_PROXY_TIMEOUT", "120"))


class UnifiedSocratesHandler(BaseHTTPRequestHandler):
    def _send_json(self, status: int, payload: Dict[str, Any]):
        try:
            response_bytes = json.dumps(payload).encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(response_bytes)))
            self.send_header("Access-Control-Allow-Origin", "*")
            self.send_header("Access-Control-Allow-Methods", "POST, GET, OPTIONS")
            self.send_header("Access-Control-Allow-Headers", "Content-Type, Accept")
            self.end_headers()
            self.wfile.write(response_bytes)
        except (BrokenPipeError, ConnectionResetError):
            pass

    def _proxy_sparql(self, method: str, query: str, fmt: str):
        try:
            if method == "GET":
                resp = requests.get(
                    SPARQL_ENDPOINT,
                    params={"query": query, "format": fmt},
                    headers={"Accept": fmt},
                    timeout=SPARQL_PROXY_TIMEOUT,
                )
            else:
                resp = requests.post(
                    SPARQL_ENDPOINT,
                    data={"query": query, "format": fmt},
                    headers={"Accept": fmt},
                    timeout=SPARQL_PROXY_TIMEOUT,
                )
        except requests.RequestException as e:
            self._send_json(502, {"error": f"SPARQL proxy error: {e}"})
            return
        # requests transparently decompresses the body, so the upstream
        # Content-Length/Content-Encoding no longer describe resp.content.
        body = resp.content
        try:
            self.send_response(resp.status_code)
            self.send_header("Content-Type", resp.headers.get("Content-Type", fmt))
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Access-Control-Allow-Origin", "*")
            self.end_headers()
            self.wfile.write(body)
        except (BrokenPipeError, ConnectionResetError):
            pass

    def do_OPTIONS(self):
        self.send_response(200)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "POST, GET, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type, Accept")
        self.end_headers()

    def do_GET(self):
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path

        if path in ("/health", "/"):
            sparql_ok = False
            try:
                sr = requests.get(
                    SPARQL_ENDPOINT,
                    params={"query": "SELECT (1 AS ?x) WHERE { ?s ?p ?o } LIMIT 1", "format": "application/sparql-results+json"},
                    headers={"Accept": "application/sparql-results+json"},
                    timeout=3,
                )
                sparql_ok = (sr.status_code == 200)
            except Exception:
                pass

            self._send_json(200, {
                "status": "ok",
                "service": "socrates-unified-server",
                "components": {
                    "vector": "ready",
                    "sparql": "connected" if sparql_ok else "unreachable",
                },
                "endpoints": ["/sparql", "/hybrid", "/search", "/health"],
            })

        elif path == "/sparql":
            params = urllib.parse.parse_qs(parsed.query)
            query = params.get("query", [""])[0]
            fmt = params.get("format", ["application/sparql-results+json"])[0]
            if not query:
                self._send_json(400, {"error": "Missing 'query' query parameter"})
                return

            self._proxy_sparql("GET", query, fmt)

        else:
            self._send_json(404, {"error": "Not Found"})

    def do_POST(self):
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path
        content_length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(content_length)

        if path == "/sparql":
            content_type = self.headers.get("Content-Type", "")
            if "application/json" in content_type:
                try:
                    payload = json.loads(body.decode("utf-8")) if body else {}
                    query = payload.get("query", "")
                    fmt = payload.get("format", "application/sparql-results+json")
                except Exception:
                    self._send_json(400, {"error": "Invalid JSON body"})
                    return
            else:
                decoded = body.decode("utf-8")
                parsed_body = urllib.parse.parse_qs(decoded)
                query = parsed_body.get("query", [decoded])[0]
                fmt = parsed_body.get("format", ["application/sparql-results+json"])[0]

            if not query:
                self._send_json(400, {"error": "Field 'query' is required"})
                return

            self._proxy_sparql("POST", query, fmt)

        elif path in ("/hybrid", "/search"):
            try:
                data = json.loads(body.decode("utf-8")) if body else {}
            except Exception:
                self._send_json(400, {"error": "Invalid JSON body"})
                return

            query = str(data.get("query", "")).strip()
            entity_types = data.get("entity_types")
            try:
                top_k = max(1, min(int(data.get("top_k", 5)), 50))
            except (TypeError, ValueError):
                self._send_json(400, {"error": "Field 'top_k' must be an integer"})
                return

            if not query:
                self._send_json(400, {"error": "Field 'query' is required"})
                return

            try:
                if path == "/hybrid":
                    results = retrieve_hybrid(query=query, top_k=top_k, entity_types=entity_types)
                    mode = "hybrid"
                else:
                    results = search_entities(query=query, entity_types=entity_types, top_k=top_k)
                    mode = "vector"
            except SparqlError as e:
                logger.error("Hybrid retrieval failed: %s", e)
                self._send_json(502, {"error": str(e)})
                return
            except Exception as e:  # keep the server answering; never drop the connection
                logger.exception("Retrieval failed")
                self._send_json(500, {"error": f"Retrieval failed: {e}"})
                return
            self._send_json(200, {"query": query, "results": results, "mode": mode})

        else:
            self._send_json(404, {"error": "Not Found"})

    def log_message(self, format: str, *args: Any):
        logger.info("%s - %s", self.address_string(), format % args)


def run_service():
    server = ThreadingHTTPServer((HOST, PORT), UnifiedSocratesHandler)
    print(f"[OK] Unified SOCrates Server (SPARQL + Hybrid + Vector) running on http://{HOST}:{PORT}")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()


if __name__ == "__main__":
    run_service()
