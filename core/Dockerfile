FROM python:3.12-slim AS build
WORKDIR /build
COPY pyproject.toml ./
COPY athena ./athena
RUN pip install --no-cache-dir --prefix=/install .

FROM python:3.12-slim
RUN useradd --create-home --uid 10001 athena
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
