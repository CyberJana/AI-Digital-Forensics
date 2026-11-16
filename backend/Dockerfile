FROM python:3.12-slim@sha256:5e2bdb1b0d542d5039cffb8181c65930093949194a65c365dfb1b0fe13a4fa5b AS build

WORKDIR /build
COPY backend/requirements.lock backend/requirements-build.lock backend/requirements-pip.lock ./
RUN python -m pip install --no-cache-dir --require-hashes -r requirements-pip.lock \
    && python -m pip install --no-cache-dir --require-hashes -r requirements-build.lock \
    && python -m pip install --no-cache-dir --require-hashes --prefix=/install -r requirements.lock
COPY backend/pyproject.toml ./pyproject.toml
COPY backend/src ./src
RUN python -m pip install --no-cache-dir --no-deps --no-build-isolation --prefix=/install .

FROM python:3.12-slim@sha256:5e2bdb1b0d542d5039cffb8181c65930093949194a65c365dfb1b0fe13a4fa5b

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app
COPY backend/requirements-pip.lock ./requirements-pip.lock
RUN python -m pip install --no-cache-dir --require-hashes -r requirements-pip.lock \
    && python -m pip uninstall --yes setuptools
RUN useradd --system --uid 10001 --create-home app
COPY --from=build /install /usr/local
COPY --chown=10001:10001 backend/alembic.ini ./alembic.ini
COPY --chown=10001:10001 backend/migrations ./migrations

USER 10001:10001
EXPOSE 8000
CMD ["uvicorn", "digital_forensics.main:app", "--host", "0.0.0.0", "--port", "8000"]
