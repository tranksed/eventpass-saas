FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

RUN useradd --create-home --shell /bin/bash appuser
WORKDIR /app

COPY pyproject.toml ./
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir fastapi uvicorn[standard] sqlalchemy[asyncio] asyncpg aiosqlite \
    pydantic pydantic-settings cryptography pyjwt pyotp httpx qrcode pillow

COPY shared_kernel ./shared_kernel
COPY services ./services

RUN mkdir -p /app/data/keys && chown -R appuser:appuser /app
USER appuser

ARG SERVICE_MODULE=services.auth_service.app:create_auth_app
ENV SERVICE_MODULE=${SERVICE_MODULE}
CMD ["sh", "-c", "uvicorn --factory ${SERVICE_MODULE} --host 0.0.0.0 --port 8000 --workers 4"]
