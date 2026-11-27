FROM python:3.12-slim AS build
WORKDIR /build
COPY pyproject.toml ./
COPY athena ./athena
RUN pip install --no-cache-dir --prefix=/install .

FROM python:3.12-slim
RUN apt-get update \
 && apt-get install -y --no-install-recommends docker-cli \
 && rm -rf /var/lib/apt/lists/*
RUN useradd --create-home --uid 10001 athena
RUN mkdir -p /work && chown athena:athena /work
COPY --from=build /install /usr/local
WORKDIR /app
COPY alembic.ini ./
COPY athena ./athena
COPY evals ./evals
USER athena
ENV PYTHONUNBUFFERED=1 PYTHONDONTWRITEBYTECODE=1
EXPOSE 8000
ENTRYPOINT ["athena"]
CMD ["serve"]
