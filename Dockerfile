# syntax=docker/dockerfile:1
#
# Two stages: dependencies are installed in a throwaway "build" stage, and
# only the finished virtualenv is copied into the final image. pip, wheel
# caches and build tooling never reach the image that runs, which means less
# for an attacker to use if they ever got code execution inside it.
#
# For fully reproducible builds, pin the base image by digest, e.g.
#   FROM python:3.13-slim@sha256:<digest>
# (`docker buildx imagetools inspect python:3.13-slim` shows the digest.)

FROM python:3.13-slim AS build
ENV PIP_NO_CACHE_DIR=1 PIP_DISABLE_PIP_VERSION_CHECK=1
RUN python -m venv /opt/venv
COPY requirements.txt /tmp/requirements.txt
# --require-hashes: pip refuses any file whose hash isn't in
# requirements.txt, so a tampered package on PyPI or a mirror can't sneak in.
# --only-binary: never run a package's setup.py at build time.
RUN /opt/venv/bin/pip install --require-hashes --only-binary=:all: -r /tmp/requirements.txt

FROM python:3.13-slim
RUN useradd --system --uid 10001 --no-create-home --shell /usr/sbin/nologin hollowwarden \
    && mkdir /data \
    && chown hollowwarden:hollowwarden /data \
    && chmod 700 /data
COPY --from=build /opt/venv /opt/venv
COPY hollowwarden /app/hollowwarden
ENV PATH=/opt/venv/bin:$PATH \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1
WORKDIR /app
USER hollowwarden
EXPOSE 8080
CMD ["python", "-m", "hollowwarden"]
