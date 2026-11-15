FROM python:3.15-slim AS build

WORKDIR /build
COPY backend/pyproject.toml ./pyproject.toml
COPY backend/src ./src
RUN python -m pip install --no-cache-dir --prefix=/install .

FROM python:3.15-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app
RUN useradd --system --uid 10001 --create-home app
COPY --from=build /install /usr/local
COPY --chown=10001:10001 backend/alembic.ini ./alembic.ini
COPY --chown=10001:10001 backend/migrations ./migrations

USER 10001:10001
EXPOSE 8000
CMD ["uvicorn", "digital_forensics.main:app", "--host", "0.0.0.0", "--port", "8000"]
