"""Database engine and session helpers enforcing isolated DBs per microservice."""

from __future__ import annotations

import asyncio
from collections.abc import AsyncIterator, Awaitable, Callable
from pathlib import Path
from typing import Any

from sqlalchemy import text
from sqlalchemy.ext.asyncio import (
    AsyncConnection,
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)
from sqlalchemy.orm import DeclarativeBase


class Base(DeclarativeBase):
    """Declarative base for microservice ORM models."""


def create_service_db(
    database_url: str,
    *,
    echo: bool = False,
) -> tuple[AsyncEngine, async_sessionmaker[AsyncSession]]:
    """Create an async SQLAlchemy engine and session factory for a single microservice."""
    if database_url.startswith("sqlite"):
        # Ensure parent directory exists for SQLite local database files
        db_part = database_url.split("///")[-1]
        if db_part and db_part != ":memory:":
            Path(db_part).parent.mkdir(parents=True, exist_ok=True)
        engine = create_async_engine(database_url, echo=echo, future=True)
    else:
        # Production PostgreSQL / PgBouncer transaction pooling requires statement_cache_size=0
        connect_args = {"statement_cache_size": 0} if "asyncpg" in database_url else {}
        engine = create_async_engine(
            database_url,
            echo=echo,
            pool_size=20,
            max_overflow=30,
            pool_pre_ping=True,
            connect_args=connect_args,
            future=True,
        )

    session_factory = async_sessionmaker(
        bind=engine,
        class_=AsyncSession,
        expire_on_commit=False,
        autoflush=False,
    )
    return engine, session_factory


async def init_db_schema(
    engine: AsyncEngine,
    metadata: Any,
    post_init: Callable[[AsyncConnection], Awaitable[None]] | None = None,
    *,
    max_attempts: int = 15,
    retry_delay_seconds: float = 1.0,
) -> None:
    """Safely initialize schema across multi-worker startups and booting Postgres containers."""
    for attempt in range(1, max_attempts + 1):
        try:
            async with engine.begin() as conn:
                if conn.dialect.name == "postgresql":
                    # Serialize concurrent DDL across uvicorn workers (--workers 4)
                    await conn.execute(text("SELECT pg_advisory_xact_lock(72839104)"))
                await conn.run_sync(metadata.create_all)
                if post_init is not None:
                    await post_init(conn)
            return
        except Exception:
            if attempt >= max_attempts:
                raise
            await asyncio.sleep(retry_delay_seconds)


async def get_db_session(
    session_factory: async_sessionmaker[AsyncSession],
) -> AsyncIterator[AsyncSession]:
    """Yield an async session with rollback on unhandled exceptions."""
    async with session_factory() as session:
        try:
            yield session
        except Exception:
            await session.rollback()
            raise
