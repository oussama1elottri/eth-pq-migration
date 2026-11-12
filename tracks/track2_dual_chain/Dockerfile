FROM python:3.11-slim

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    curl \
    git \
    netcat-openbsd \
    && rm -rf /var/lib/apt/lists/*

COPY core-crypto/requirements.txt /app/core-crypto/requirements.txt
RUN pip install --no-cache-dir -r /app/core-crypto/requirements.txt

COPY . /app

ENV PYTHONUNBUFFERED=1
CMD ["python", "tracks/track2_dual_chain/relayer.py"]
