FROM python:3.12-slim

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1

# Build deps (purged later) + libmagic1 kept at runtime for python-magic,
# which is a transitive dependency of pycti (file type detection).
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        build-essential git ca-certificates \
        libmagic1 libmagic-dev && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /opt/connector

COPY src/requirements.txt /opt/connector/requirements.txt
RUN pip install --upgrade pip && \
    pip install --no-cache-dir -r /opt/connector/requirements.txt

COPY src/ /opt/connector/

# Strip build-only packages, keep libmagic1 (runtime).
RUN apt-get purge -y --auto-remove build-essential git libmagic-dev && \
    rm -rf /root/.cache/pip

ENV PYTHONPATH=/opt/connector

CMD ["python", "main.py"]
