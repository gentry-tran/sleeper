"""
FLAG reporter -- watches Docker logs for FLAG pattern leakage.

Used by the CLI's 'watch' command to detect when a prompt injection
successfully causes the LLM agent to leak the FLAG.
"""

import re
import subprocess
import sys
import time
from datetime import datetime


FLAG_PATTERN = re.compile(r"FLAG\{[^}]+\}")


def watch_logs(container_name: str = "mqtt-injection-lab-vulnerable-agent-1",
               timeout: int = 0):
    """Stream Docker logs and watch for FLAG pattern.

    Args:
        container_name: Docker container to tail logs from.
        timeout: Stop after this many seconds (0 = run forever).
    """
    print(f"[REPORTER] Watching container '{container_name}' for FLAG pattern...")
    print(f"[REPORTER] Press Ctrl+C to stop")
    print()

    start = time.time()

    try:
        proc = subprocess.Popen(
            ["docker", "logs", "-f", "--tail", "100", container_name],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
        )

        for line in proc.stdout:
            line = line.rstrip()

            # Check for FLAG
            match = FLAG_PATTERN.search(line)
            if match:
                flag = match.group(0)
                ts = datetime.now().strftime("%H:%M:%S")
                print()
                print("=" * 60)
                print(f"  FLAG CAPTURED at {ts}")
                print(f"  {flag}")
                print("=" * 60)
                print()
                print(f"  Full line: {line}")
                print()

            # Print all lines with a prefix
            sys.stdout.write(f"  | {line}\n")
            sys.stdout.flush()

            # Timeout check
            if timeout > 0 and (time.time() - start) > timeout:
                print(f"\n[REPORTER] Timeout after {timeout}s")
                break

    except FileNotFoundError:
        print("[REPORTER] ERROR: 'docker' command not found. Is Docker installed?")
        sys.exit(1)
    except KeyboardInterrupt:
        print("\n[REPORTER] Stopped")
    finally:
        try:
            proc.terminate()
        except Exception:
            pass


def check_flag_in_output(text: str) -> list[str]:
    """Check a string for FLAG patterns and return all matches."""
    return FLAG_PATTERN.findall(text)
