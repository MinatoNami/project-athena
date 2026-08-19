# Separate image on purpose. No model client library is installed here, so a
# compromised reasoning layer has nothing to reach even if it reached this host.
# See docs/TECHNICAL_DESIGN.md §10.
FROM python:3.12-slim AS build
WORKDIR /build
COPY pyproject.toml ./
COPY athena_executor ./athena_executor
RUN pip install --no-cache-dir --prefix=/install .

FROM python:3.12-slim
RUN useradd --create-home --uid 10002 executor
COPY --from=build /install /usr/local
WORKDIR /app
COPY athena_executor ./athena_executor
USER executor
ENV PYTHONUNBUFFERED=1 PYTHONDONTWRITEBYTECODE=1
ENTRYPOINT ["athena-executor"]
