from collections.abc import Generator
from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker

from app.config import settings

connect_args = {"check_same_thread": False} if settings.database_url.startswith("sqlite") else {}

engine = create_engine(
    settings.database_url,
    connect_args=connect_args,
    echo=False,
    future=True,
)

SessionLocal = sessionmaker(
    bind=engine,
    autoflush=False,
    autocommit=False,
    expire_on_commit=False,

    class_=Session,
)

def get_db() -> Generator[Session, None, None]:

    """Предоставляет сессию базы данных на время обработки запроса и закрывает её после использования.

    Возвращает:
        Результат выполнения операции (тип: Generator[Session, None, None]).
    """
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()