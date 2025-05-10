# syntax=docker/dockerfile:latest

FROM debian:bookworm-slim AS base

RUN apt-get update && apt-get install -y --no-install-recommends \
    socat \
    python3 \
    python3-pip \
    python3-venv \
    sagemath \
    build-essential \
    gcc \
    g++ \
    libgmp-dev \
    libmpfr-dev \
    libmpc-dev \
    ca-certificates

RUN pip install --break-system-packages setuptools wheel
RUN pip install --break-system-packages pycryptodome

COPY main.py Curve25519.py ECDHE.py ECElGamal.py util.py /

ENV FLAG "EPFL{Prim41ity_of_e11iptic_curv3_0rder_m4tter5}"

CMD echo "Starting Server..."; socat TCP-LISTEN:5000,fork EXEC:"python3 /main.py"
