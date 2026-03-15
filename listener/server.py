"""
Persistent callback listener — catches phone-home exfiltration.

Stores EVERY callback in SQLite so nothing is lost across restarts.
Can run for hours, days, or weeks waiting for a phone-home.

Routes:
  ANY /*                → Store the callback (the phone-home landing)
  GET /api/status       → Listener uptime and stats
  GET /api/callbacks    → List stored callbacks (JSON)
  DELETE /api/callbacks → Clear all stored callbacks
"""

import json
import os
import sqlite3
import sys
import time
import uuid
from datetime import datetime, timezone
from http.server import HTTPServer, BaseHTTPRequestHandler
from pathlib import Path
from urllib.parse import urlparse, parse_qs

DATA_DIR = Path(os.environ.get("DATA_DIR", "/data"))
DB_PATH = DATA_DIR / "callbacks.db"
PORT = int(os.environ.get("LISTENER_PORT", "9999"))
START_TIME = time.time()

FLAG_PATTERN = "FLAG{"


def init_db():
    """Create the SQLite database and table if they don't exist."""
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(DB_PATH))
    conn.execute("""CREATE TABLE IF NOT EXISTS callbacks (
        id TEXT PRIMARY KEY,
        received_at TEXT NOT NULL,
        method TEXT NOT NULL,
        path TEXT NOT NULL,
        query_params TEXT,
        headers TEXT,
        body TEXT,
        source_ip TEXT,
        flag_found TEXT,
        correlation_id TEXT
    )""")
    conn.commit()
    conn.close()


def store_callback(method, path, headers_dict, body, source_ip):
    """Store a callback in SQLite. Returns (callback_id, flag_or_none)."""
    parsed = urlparse(path)
    params = parse_qs(parsed.query)

    # Extract correlation ID if present
    correlation = params.pop("_cid", [None])[0]

    # Scan for FLAG in path + body
    full_text = path + " " + body
    flag = None
    if FLAG_PATTERN in full_text:
        start = full_text.index(FLAG_PATTERN)
        try:
            end = full_text.index("}", start) + 1
            flag = full_text[start:end]
        except ValueError:
            flag = full_text[start:start + 80]

    cb_id = uuid.uuid4().hex[:8]
    now = datetime.now(timezone.utc).isoformat()

    conn = sqlite3.connect(str(DB_PATH))
    conn.execute(
        """INSERT INTO callbacks
           (id, received_at, method, path, query_params, headers, body,
            source_ip, flag_found, correlation_id)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
        (cb_id, now, method, parsed.path,
         json.dumps(dict(params)) if params else None,
         json.dumps(headers_dict),
         body[:4096] if body else None,
         source_ip, flag, correlation),
    )
    conn.commit()
    conn.close()
    return cb_id, flag, correlation, params


class CallbackHandler(BaseHTTPRequestHandler):
    """Handles both phone-home callbacks and API queries."""

    def _is_api(self):
        return self.path.startswith("/api/")

    # ── API handlers ──────────────────────────────────────────────

    def _handle_api(self, method):
        parsed = urlparse(self.path)
        route = parsed.path

        if route == "/api/status" and method == "GET":
            self._api_status()
        elif route == "/api/callbacks" and method == "GET":
            self._api_list_callbacks(parsed)
        elif route == "/api/callbacks" and method == "DELETE":
            self._api_clear_callbacks()
        elif route == "/api/ping":
            self._json_response(200, {"pong": True})
        else:
            self._json_response(404, {"error": "unknown endpoint"})

    def _api_status(self):
        conn = sqlite3.connect(str(DB_PATH))
        total = conn.execute("SELECT COUNT(*) FROM callbacks").fetchone()[0]
        flags = conn.execute(
            "SELECT COUNT(*) FROM callbacks WHERE flag_found IS NOT NULL"
        ).fetchone()[0]
        latest = conn.execute(
            "SELECT received_at FROM callbacks ORDER BY received_at DESC LIMIT 1"
        ).fetchone()
        conn.close()

        uptime = int(time.time() - START_TIME)
        days, rem = divmod(uptime, 86400)
        hours, rem = divmod(rem, 3600)
        minutes, _ = divmod(rem, 60)

        self._json_response(200, {
            "uptime_seconds": uptime,
            "uptime_human": f"{days}d {hours}h {minutes}m",
            "total_callbacks": total,
            "flags_captured": flags,
            "last_callback": latest[0] if latest else None,
            "db_path": str(DB_PATH),
        })

    def _api_list_callbacks(self, parsed):
        params = parse_qs(parsed.query)
        limit = int(params.get("limit", ["50"])[0])
        since = params.get("since", [None])[0]

        conn = sqlite3.connect(str(DB_PATH))
        conn.row_factory = sqlite3.Row
        if since:
            rows = conn.execute(
                "SELECT * FROM callbacks WHERE received_at > ? "
                "ORDER BY received_at DESC LIMIT ?",
                (since, limit),
            ).fetchall()
        else:
            rows = conn.execute(
                "SELECT * FROM callbacks ORDER BY received_at DESC LIMIT ?",
                (limit,),
            ).fetchall()
        conn.close()
        self._json_response(200, [dict(r) for r in rows])

    def _api_clear_callbacks(self):
        conn = sqlite3.connect(str(DB_PATH))
        count = conn.execute("SELECT COUNT(*) FROM callbacks").fetchone()[0]
        conn.execute("DELETE FROM callbacks")
        conn.commit()
        conn.close()
        self._json_response(200, {"cleared": count})

    # ── Phone-home handler ────────────────────────────────────────

    def _handle_callback(self, method, body=b""):
        body_str = body.decode("utf-8", errors="replace")
        headers_dict = {k: v for k, v in self.headers.items()}

        cb_id, flag, correlation, params = store_callback(
            method, self.path, headers_dict, body_str, self.client_address[0]
        )

        # Console output
        ts = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
        print(f"\n{'=' * 60}")
        print(f"  CALLBACK #{cb_id}  |  {ts}")
        print(f"  {method} {self.path}")
        if correlation:
            print(f"  Correlation ID: {correlation}")
        if params:
            for k, v in params.items():
                print(f"    {k} = {v[0]}")
        if body_str:
            print(f"  Body: {body_str[:300]}")
        if flag:
            print()
            print(f"  {'!' * 46}")
            print(f"  !!! FLAG EXFILTRATED: {flag}")
            print(f"  !!! PHONE-HOME SUCCEEDED")
            print(f"  {'!' * 46}")
        print(f"{'=' * 60}")
        sys.stdout.flush()

        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()
        self.wfile.write(b"OK")

    # ── HTTP method dispatch ──────────────────────────────────────

    def do_GET(self):
        if self._is_api():
            self._handle_api("GET")
        else:
            self._handle_callback("GET")

    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(length) if length else b""
        if self._is_api():
            self._handle_api("POST")
        else:
            self._handle_callback("POST", body)

    def do_PUT(self):
        length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(length) if length else b""
        self._handle_callback("PUT", body)

    def do_DELETE(self):
        if self._is_api():
            self._handle_api("DELETE")
        else:
            self._handle_callback("DELETE")

    def do_OPTIONS(self):
        self.send_response(204)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
        self.end_headers()

    # ── Helpers ───────────────────────────────────────────────────

    def _json_response(self, code, data):
        body = json.dumps(data, indent=2).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, fmt, *args):
        pass  # Suppress default request logging


def main():
    init_db()
    server = HTTPServer(("0.0.0.0", PORT), CallbackHandler)

    print("=" * 60)
    print("  PERSISTENT CALLBACK LISTENER")
    print(f"  Port:     {PORT}")
    print(f"  Database: {DB_PATH}")
    print(f"  API:      http://localhost:{PORT}/api/status")
    print()
    print("  This listener stores ALL callbacks in SQLite.")
    print("  Safe to run for hours, days, or weeks.")
    print("  Restart-safe — data persists across container restarts.")
    print("=" * 60)
    print()
    print("Waiting for phone-home connections...")
    print()
    sys.stdout.flush()

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nShutting down listener")
        server.shutdown()


if __name__ == "__main__":
    main()
