FROM python:3.12-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY config.py .
COPY reporter.py .
COPY inject_cli.py .
COPY templates/ templates/

ENTRYPOINT ["python", "-u", "inject_cli.py"]
