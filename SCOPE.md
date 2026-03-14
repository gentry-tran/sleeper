# Responsible Use Statement

## Purpose

This lab is a **controlled educational environment** for demonstrating stored prompt injection attacks in IoT-to-LLM pipelines. It is designed for:

- Security researchers studying LLM prompt injection vectors
- Developers learning to build defences against data-poisoning attacks
- Presenters demonstrating AI security risks in conference talks and workshops
- CTF organisers creating realistic AI security challenges

## Scope Limitations

- **Local only.** All services run inside Docker containers on your machine. No external network access is required or intended.
- **No real data.** The telemetry data is synthetic. The FLAG is a static string with no operational value.
- **No real LLM API keys.** Ollama runs locally -- no cloud API calls are made.
- **Intentionally vulnerable.** The vulnerable agent is deliberately built without defences. This is not a bug -- it is the teaching tool.

## Prohibited Uses

- Do not deploy these vulnerable components in production environments.
- Do not use the attack techniques demonstrated here against systems you do not own or have explicit authorisation to test.
- Do not modify this lab to target real IoT infrastructure, real databases, or real LLM APIs without proper authorisation and scoping.

## Remediation Requirement

If you use this lab for training or demonstration, you **must** also demonstrate the patched agent (`patched_agent.py`) and explain the three defence layers:

1. **Input sanitisation** -- strip or escape injected instructions in data fields
2. **System prompt guardrails** -- constrain LLM behaviour with explicit role boundaries
3. **Least-privilege access** -- restrict the DB user so sensitive tables are inaccessible

Security education without remediation guidance is incomplete.

## Licence

This lab is provided as-is for educational purposes. The authors assume no liability for misuse.
