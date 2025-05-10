# syntax=docker/dockerfile:latest

FROM docker.io/python:slim@sha256:f41a75c9cee9391c09e0139f7b49d4b1fbb119944ec740ecce4040626dc07bed AS base

RUN --mount=type=cache,target=/root/.cache/pip,sharing=locked \
     pip install pycryptodome

FROM pwn.red/jail@sha256:ee52ad5fd6cfed7fd8ea30b09792a6656045dd015f9bef4edbbfa2c6e672c28c

COPY --from=base / /srv
COPY --chmod=0755 main.py /srv/app/run
COPY --chmod=0644 HCom.py /srv/app/HCom.py

ENV JAIL_TIME 120
ENV JAIL_CONNS_PER_IP 5
ENV JAIL_MEM 20M
ENV JAIL_ENV_FLAG "EPFL{fake_flag}"
