FROM python:3.12-slim AS base

LABEL maintainer="Mariusz Gebala <kontakt@haitmg.pl>"
LABEL org.opencontainers.image.source="https://github.com/gebalamariusz/cloud-audit"
LABEL org.opencontainers.image.description="Scan your cloud infrastructure for security, cost, and reliability issues."

WORKDIR /app

COPY pyproject.toml README.md ./
COPY src/ src/

RUN pip install --no-cache-dir .

ENTRYPOINT ["cloud-audit"]
CMD ["scan", "--help"]
