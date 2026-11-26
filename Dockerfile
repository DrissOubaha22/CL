FROM python:3.12-slim AS base

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /app

RUN apt-get update \
 && apt-get install -y --no-install-recommends libpq5 \
 && rm -rf /var/lib/apt/lists/*

COPY pyproject.toml README.md ./
COPY src ./src
RUN pip install --no-cache-dir .

COPY alembic.ini alembic_tenant.ini ./
COPY migrations ./migrations
COPY migrations_tenant ./migrations_tenant

# The intel ETL needs no privileges inside the container.
RUN useradd --create-home --uid 10001 aegis
USER aegis

# The API listens here when this image is run as the portal;
# workers and the CLI ignore it.
EXPOSE 8000

ENTRYPOINT ["aegis"]
CMD ["--help"]
