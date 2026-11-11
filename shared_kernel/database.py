"""Database engine and session helpers enforcing isolated DBs per microservice."""

from __future__ import annotations

from collections.abc import AsyncIterator
from pathlib import Path

from sqlalchemy.ext.asyncio import (
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
        # Production PostgreSQL / PgBouncer pooling parameters
        engine = create_async_engine(
            database_url,
            echo=echo,
            pool_size=20,
            max_overflow=30,
            pool_pre_ping=True,
            future=True,
        )

    session_factory = async_sessionmaker(
        bind=engine,
        class_=AsyncSession,
        expire_on_commit=False,
        autoflush=False,
    )
    return engine, session_factory


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
