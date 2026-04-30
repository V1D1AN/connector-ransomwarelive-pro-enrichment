FROM python:3.12-slim

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1

RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        build-essential libmagic-dev git ca-certificates && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /opt/connector

COPY src/requirements.txt /opt/connector/requirements.txt
RUN pip install --upgrade pip && \
    pip install --no-cache-dir -r /opt/connector/requirements.txt

COPY src/ /opt/connector/

RUN apt-get purge -y --auto-remove build-essential git && \
    rm -rf /root/.cache/pip

ENV PYTHONPATH=/opt/connector

CMD ["python", "main.py"]
