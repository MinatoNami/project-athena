FROM python:3.12-slim AS build
WORKDIR /build
COPY pyproject.toml ./
COPY athena ./athena
RUN pip install --no-cache-dir --prefix=/install .

FROM python:3.12-slim
# `docker-cli`, deliberately not `docker.io`: Debian's docker.io package ships the
# daemon and no client. The worker only needs a client to launch sibling scanner
# containers through the mounted socket — no daemon belongs in this image.
RUN apt-get update \
 && apt-get install -y --no-install-recommends docker-cli \
 && rm -rf /var/lib/apt/lists/*
RUN useradd --create-home --uid 10001 athena
# A new named volume inherits ownership from the image's directory, so create it
# owned by the runtime user rather than root.
RUN mkdir -p /work && chown athena:athena /work
COPY --from=build /install /usr/local
WORKDIR /app
COPY alembic.ini ./
COPY athena ./athena
USER athena
ENV PYTHONUNBUFFERED=1 PYTHONDONTWRITEBYTECODE=1
EXPOSE 8000
# No HEALTHCHECK here: this image runs the api, worker, and scheduler, and an HTTP
# probe is only meaningful for the api. Each service declares its own in compose.
ENTRYPOINT ["athena"]
CMD ["serve"]
