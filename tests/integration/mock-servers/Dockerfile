FROM python:3.11-slim

RUN pip install --no-cache-dir \
    "pydantic>=2.7" \
    "tenacity>=8.2" \
    "asyncssh>=2.14" \
    "structlog>=24.1" \
    "pyyaml>=6.0" \
    "jh2>=5.0"

WORKDIR /workspace
ENV PYTHONPATH=/workspace/src
