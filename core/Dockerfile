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
HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
    CMD python -c "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8000/healthz',timeout=3).status==200 else 1)"
ENTRYPOINT ["athena"]
CMD ["serve"]
