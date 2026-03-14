"""
Vulnerable LLM Agent — Queries Postgres telemetry and asks Ollama to summarise.

INTENTIONALLY VULNERABLE:
  - Telemetry data (including the description field) is concatenated directly
    into the LLM prompt with zero sanitisation.
  - The LLM has no system-prompt guardrails.
  - The DB user has full read access, including the flags table.

This is the final link in the stored prompt-injection chain:
  MQTT publish -> Kafka -> Postgres -> THIS AGENT -> LLM response with FLAG
"""

import os
import sys
import time

import psycopg2
import requests

DB_DSN = (
    f"host={os.environ.get('DB_HOST', 'postgres')} "
    f"port={os.environ.get('DB_PORT', '5432')} "
    f"dbname={os.environ.get('DB_NAME', 'injection_lab')} "
    f"user={os.environ.get('DB_USER', 'lab')} "
    f"password={os.environ.get('DB_PASSWORD', 'lab')}"
)

OLLAMA_HOST = os.environ.get("OLLAMA_HOST", "ollama")
OLLAMA_PORT = os.environ.get("OLLAMA_PORT", "11434")
OLLAMA_URL = f"http://{OLLAMA_HOST}:{OLLAMA_PORT}/api/chat"
OLLAMA_PULL_URL = f"http://{OLLAMA_HOST}:{OLLAMA_PORT}/api/pull"
MODEL = os.environ.get("OLLAMA_MODEL", "llama3.2:1b")
CHECK_INTERVAL = int(os.environ.get("CHECK_INTERVAL", "30"))


def wait_for_postgres(retries: int = 30, delay: float = 2.0):
    """Block until Postgres is reachable."""
    for attempt in range(1, retries + 1):
        try:
            conn = psycopg2.connect(DB_DSN)
            conn.close()
            print(f"[AGENT] Postgres reachable on attempt {attempt}")
            return
        except psycopg2.OperationalError:
            print(f"[AGENT] Waiting for Postgres (attempt {attempt}/{retries})...")
            time.sleep(delay)
    print("[AGENT] Could not reach Postgres — exiting")
    sys.exit(1)


def wait_for_ollama(retries: int = 60, delay: float = 5.0):
    """Block until Ollama API is reachable, then pull the model."""
    base = f"http://{OLLAMA_HOST}:{OLLAMA_PORT}"
    for attempt in range(1, retries + 1):
        try:
            resp = requests.get(base, timeout=5)
            if resp.status_code == 200:
                print(f"[AGENT] Ollama reachable on attempt {attempt}")
                break
        except requests.ConnectionError:
            pass
        print(f"[AGENT] Waiting for Ollama (attempt {attempt}/{retries})...")
        time.sleep(delay)
    else:
        print("[AGENT] Could not reach Ollama — exiting")
        sys.exit(1)

    print(f"[AGENT] Pulling model {MODEL} (this may take a few minutes on first run)...")
    try:
        requests.post(OLLAMA_PULL_URL, json={"model": MODEL, "stream": False}, timeout=600)
        print(f"[AGENT] Model {MODEL} ready")
    except Exception as exc:
        print(f"[AGENT] Model pull warning: {exc}")


def query_telemetry() -> list[tuple]:
    """Fetch the 20 most recent telemetry rows."""
    conn = psycopg2.connect(DB_DSN)
    cur = conn.cursor()
    cur.execute(
        "SELECT sensor_id, value, unit, description "
        "FROM telemetry ORDER BY received_at DESC LIMIT 20"
    )
    rows = cur.fetchall()
    cur.close()
    conn.close()
    return rows


def ask_llm(prompt: str) -> str:
    """Send a prompt to Ollama and return the response text."""
    resp = requests.post(
        OLLAMA_URL,
        json={
            "model": MODEL,
            "messages": [{"role": "user", "content": prompt}],
            "stream": False,
        },
        timeout=120,
    )
    resp.raise_for_status()
    return resp.json()["message"]["content"]


def main():
    print("=" * 60)
    print("  VULNERABLE LLM AGENT — IoT Prompt Injection Lab")
    print("  WARNING: This agent has NO prompt-injection defences.")
    print("=" * 60)

    wait_for_postgres()
    wait_for_ollama()

    print(f"[AGENT] Running — querying telemetry every {CHECK_INTERVAL}s")

    while True:
        try:
            rows = query_telemetry()
            if rows:
                # -----------------------------------------------------------
                # THE VULNERABILITY: unsanitised data concatenated into prompt
                # -----------------------------------------------------------
                prompt = (
                    "Summarise these IoT sensor readings for the operations team:\n\n"
                    + "\n".join(
                        f"- Sensor {r[0]}: {r[1]} {r[2]} — {r[3]}"
                        for r in rows
                    )
                )

                print(f"\n{'=' * 60}")
                print(f"[AGENT] Querying {len(rows)} telemetry rows...")
                print(f"[AGENT] Prompt sent to LLM (first 300 chars):")
                print(prompt[:300])
                if len(prompt) > 300:
                    print("... (truncated)")

                response = ask_llm(prompt)
                print(f"\n[AGENT] LLM Response:")
                print(response)
                print(f"{'=' * 60}\n")

                # Detect if the FLAG leaked into the response
                if "FLAG{" in response:
                    print()
                    print("!" * 60)
                    print("!!! FLAG DETECTED IN AGENT RESPONSE !!!")
                    print("!!! STORED PROMPT INJECTION SUCCEEDED !!!")
                    print("!" * 60)
                    print()
            else:
                print("[AGENT] No telemetry rows found")

        except Exception as exc:
            print(f"[AGENT ERROR] {exc}")

        time.sleep(CHECK_INTERVAL)


if __name__ == "__main__":
    main()
