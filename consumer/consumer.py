"""
Kafka -> Postgres telemetry writer.

INTENTIONALLY VULNERABLE: No sanitisation is performed on any field.
This is the core of the stored-injection attack surface — payloads
injected via MQTT flow through Kafka and land in Postgres untouched,
where the LLM agent later reads them.
"""

import json
import os
import sys
import time

import psycopg2
from confluent_kafka import Consumer, KafkaError, KafkaException

KAFKA_BOOTSTRAP = os.environ.get("KAFKA_BOOTSTRAP", "kafka:29092")
KAFKA_TOPIC = os.environ.get("KAFKA_TOPIC", "telemetry.events")
KAFKA_GROUP = os.environ.get("KAFKA_GROUP", "telemetry-writer")

DB_HOST = os.environ.get("DB_HOST", "postgres")
DB_PORT = int(os.environ.get("DB_PORT", "5432"))
DB_NAME = os.environ.get("DB_NAME", "injection_lab")
DB_USER = os.environ.get("DB_USER", "lab")
DB_PASS = os.environ.get("DB_PASSWORD", "lab")


def connect_db(retries: int = 30, delay: float = 2.0):
    """Connect to Postgres with retries."""
    for attempt in range(1, retries + 1):
        try:
            conn = psycopg2.connect(
                host=DB_HOST, port=DB_PORT, dbname=DB_NAME,
                user=DB_USER, password=DB_PASS,
            )
            conn.autocommit = True
            print(f"[CONSUMER] Connected to Postgres on attempt {attempt}")
            return conn
        except psycopg2.OperationalError as exc:
            print(f"[CONSUMER] Postgres not ready (attempt {attempt}/{retries}): {exc}")
            time.sleep(delay)
    print("[CONSUMER] Failed to connect to Postgres after retries — exiting")
    sys.exit(1)


def create_consumer(retries: int = 30, delay: float = 2.0):
    """Create Kafka consumer with retries."""
    conf = {
        "bootstrap.servers": KAFKA_BOOTSTRAP,
        "group.id": KAFKA_GROUP,
        "auto.offset.reset": "earliest",
        "enable.auto.commit": True,
    }
    for attempt in range(1, retries + 1):
        try:
            consumer = Consumer(conf)
            consumer.subscribe([KAFKA_TOPIC])
            print(f"[CONSUMER] Subscribed to Kafka topic '{KAFKA_TOPIC}' on attempt {attempt}")
            return consumer
        except KafkaException as exc:
            print(f"[CONSUMER] Kafka not ready (attempt {attempt}/{retries}): {exc}")
            time.sleep(delay)
    print("[CONSUMER] Failed to connect to Kafka after retries — exiting")
    sys.exit(1)


def insert_telemetry(conn, record: dict):
    """
    Insert a telemetry record into Postgres.

    !! NO SANITISATION — this is the vulnerability !!
    The description field (and all others) are stored exactly as received.
    """
    cur = conn.cursor()
    cur.execute(
        """INSERT INTO telemetry (sensor_id, value, unit, description)
           VALUES (%s, %s, %s, %s)""",
        (
            record.get("sensor_id", "UNKNOWN"),
            record.get("value"),
            record.get("unit", ""),
            record.get("description", ""),  # <-- Stored prompt injection lands here
        ),
    )
    cur.close()


def main():
    print("[CONSUMER] Starting Kafka -> Postgres telemetry writer")
    print("[CONSUMER] WARNING: No input sanitisation — vulnerable by design")

    conn = connect_db()
    consumer = create_consumer()

    try:
        while True:
            msg = consumer.poll(timeout=1.0)
            if msg is None:
                continue
            if msg.error():
                if msg.error().code() == KafkaError._PARTITION_EOF:
                    continue
                print(f"[CONSUMER] Kafka error: {msg.error()}")
                continue

            try:
                payload = json.loads(msg.value().decode("utf-8"))
                insert_telemetry(conn, payload)
                print(f"[CONSUMER] Stored telemetry: sensor_id={payload.get('sensor_id', '?')} "
                      f"value={payload.get('value', '?')} "
                      f"description_len={len(payload.get('description', ''))}")
            except json.JSONDecodeError:
                print(f"[CONSUMER] Skipping non-JSON message: {msg.value()[:100]}")
            except psycopg2.Error as exc:
                print(f"[CONSUMER] DB write error: {exc}")
                # Reconnect on DB errors
                try:
                    conn.close()
                except Exception:
                    pass
                conn = connect_db()

    except KeyboardInterrupt:
        print("[CONSUMER] Shutting down")
    finally:
        consumer.close()
        conn.close()


if __name__ == "__main__":
    main()
