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
