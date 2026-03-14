FROM python:3.12-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY vulnerable_agent.py .
COPY patched_agent.py .

# Default: run the vulnerable agent
CMD ["python", "-u", "vulnerable_agent.py"]
