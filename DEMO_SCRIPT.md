# Demo Script — Sleeper

Presenter guide. See [README.md](README.md) for setup and full documentation.

---

## Setup (before demo)

```bash
docker compose up -d
pip install -r cli/requirements.txt
python cli/sleeper.py init --properties .properties
python cli/sleeper.py status   # All components should show UP
```

Wait for Ollama to pull models (~1-2 min on first run):
```bash
docker compose logs -f vulnerable-agent   # Wait for "Running"
```

---

## Part 1: Architecture (3 min)

Draw the pipeline:
```
MQTT → Kafka → Postgres → LLM Agent → Response
 ↑                              ↓
Attacker                   FLAG leaks
publishes                  (or phones home)
poisoned data
```

Key point: **no layer sanitises the data**. Whatever goes in via MQTT arrives unchanged in the LLM prompt.

---

## Part 2: Canary (2 min)

```bash
python cli/sleeper.py fire canary
# Wait 30 seconds...
python cli/sleeper.py listen check
```

If you see a `/canary` callback → the full chain works. Proceed.

---

## Part 3: The Attack (5 min)

```bash
python cli/sleeper.py fire phone-home
# Wait 30 seconds...
python cli/sleeper.py listen check
```

**What to point out:**
1. The payload was just a string in a "description" field
2. It flowed through 4 infrastructure layers untouched
3. The LLM followed the injected SQL instruction
4. The FLAG was sent to the attacker's callback listener
5. The listener persists — it can wait hours, days, or weeks

---

## Part 4: Other Scenarios (5 min, optional)

```bash
python cli/sleeper.py fire list
python cli/sleeper.py fire recon
python cli/sleeper.py fire tool-hijack
python cli/sleeper.py fire persistence
```

---

## Part 5: The Fix (5 min)

```bash
docker compose stop vulnerable-agent
# Uncomment patched-agent in docker-compose.yml
docker compose up -d patched-agent
python cli/sleeper.py fire phone-home
docker compose logs -f patched-agent
```

Three defence layers: input sanitisation, system prompt guardrails, least-privilege DB.

---

## Cleanup

```bash
docker compose down -v
```
