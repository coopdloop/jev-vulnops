"""Stdlib web UI: dashboard + live triage streamed over Server-Sent Events.

No new dependencies: ThreadingHTTPServer serves the static dashboard and a
SSE endpoint that runs real Jev triage, emitting one event per vuln as it
lands so the UI shows the classifiers working in real time.
"""

from __future__ import annotations

import json
import time
import webbrowser
from dataclasses import asdict
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, urlparse

from .client import MODELS, PRICE_PER_MTTOK, TypeSafeLiveClient, provider_label
from .pipeline import triage
from .questions import ALL_QUESTIONS, wire_all

STATIC = Path(__file__).parent / "static"
MIME = {".html": "text/html", ".css": "text/css", ".js": "text/javascript"}


def _sse(event: str, data: Any) -> bytes:
    return f"event: {event}\ndata: {json.dumps(data, default=str)}\n\n".encode()


def _questions_payload() -> list[dict[str, Any]]:
    return [{"name": name, **q} for name, q in wire_all(ALL_QUESTIONS).items()]


def _meta_payload(vulns: list[dict[str, Any]], dataset: str) -> dict[str, Any]:
    """Serves what the UI must not hardcode: route, pricing, models, dataset."""
    return {
        "provider": provider_label(),
        "models": list(MODELS),
        "price_per_mtok_in": PRICE_PER_MTTOK,
        "questions": len(ALL_QUESTIONS),
        "vuln_count": len(vulns),
        "dataset": dataset,
    }


def _make_handler(client: TypeSafeLiveClient, vulns: list[dict[str, Any]], meta: dict[str, Any]):
    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *args):  # quiet
            pass

        def _send(self, body: bytes, content_type: str, status: int = 200):
            self.send_response(status)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def _json(self, obj: Any, status: int = 200):
            self._send(json.dumps(obj, default=str).encode(), "application/json", status)

        def do_GET(self):
            url = urlparse(self.path)
            if url.path == "/":
                self._send((STATIC / "index.html").read_bytes(), "text/html")
            elif url.path.startswith("/static/"):
                self._static(url.path)
            elif url.path == "/api/vulns":
                self._json(vulns)
            elif url.path == "/api/questions":
                self._json(_questions_payload())
            elif url.path == "/api/meta":
                self._json(meta)
            elif url.path == "/api/triage/stream":
                self._stream(url.query)
            else:
                self._json({"error": "not found"}, 404)

        def do_POST(self):
            url = urlparse(self.path)
            if url.path != "/api/ask":
                return self._json({"error": "not found"}, 404)
            length = int(self.headers.get("Content-Length", 0))
            try:
                body = json.loads(self.rfile.read(length) or b"{}")
                started = time.perf_counter()
                raw = client.ask_raw(
                    body.get("state") or {},
                    body.get("questions") or {},
                    model=body.get("model") or None,
                )
                latency_ms = round((time.perf_counter() - started) * 1000, 1)
                self._json({"ok": True, "latency_ms": latency_ms, "response": raw})
            except Exception as exc:
                self._json({"ok": False, "error": str(exc)}, 400)

        def _static(self, path: str):
            target = (STATIC / path.removeprefix("/static/")).resolve()
            if not target.is_file() or STATIC.resolve() not in target.parents:
                return self._json({"error": "not found"}, 404)
            self._send(target.read_bytes(), MIME.get(target.suffix, "application/octet-stream"))

        def _stream(self, query: str):
            params = parse_qs(query)
            threshold = float(params.get("threshold", ["0.75"])[0])
            model = params.get("model", [""])[0] or None

            self.send_response(200)
            self.send_header("Content-Type", "text/event-stream")
            self.send_header("Cache-Control", "no-cache")
            self.end_headers()

            def emit(event: str, data: Any) -> bool:
                try:
                    self.wfile.write(_sse(event, data))
                    return True
                except (BrokenPipeError, ConnectionResetError):
                    return False

            if not emit("run_start", {"total": len(vulns), "model": model or "default", "threshold": threshold}):
                return
            for v in vulns:
                if not emit("vuln_start", {"cve_id": v["cve_id"], "asset": v["asset"]["name"]}):
                    return
                try:
                    decision = triage(client, v, threshold, model=model)
                    if not emit("vuln_done", asdict(decision)):
                        return
                except Exception as exc:  # surface API errors in the feed
                    if not emit("vuln_error", {"cve_id": v["cve_id"], "error": str(exc)}):
                        return
            emit("run_done", {})

    return Handler


def run_web(
    client: TypeSafeLiveClient,
    vulns: list[dict[str, Any]],
    port: int = 8765,
    open_browser: bool = True,
    dataset: str = "built-in fixtures",
) -> int:
    server = ThreadingHTTPServer(("127.0.0.1", port), _make_handler(client, vulns, _meta_payload(vulns, dataset)))
    url = f"http://127.0.0.1:{port}"
    print(f"jev-vulnops web UI at {url} — Ctrl-C to stop")
    if open_browser:
        webbrowser.open(url)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nstopped")
    finally:
        server.server_close()
    return 0
