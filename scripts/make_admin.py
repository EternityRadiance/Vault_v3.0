from __future__ import annotations
import sys
from pathlib import Path
from sqlalchemy import select

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from app.db.session import SessionLocal
from app.models.user import User

def main() -> int:
    """Запускает основную операцию сценария командной строки.

    Возвращает:
        Результат выполнения операции (тип: int).
    """
    if len(sys.argv) < 2:
        print("Usage: python scripts/make_admin.py <email>", file=sys.stderr)
        return 1

    email = sys.argv[1].strip().lower()

    db = SessionLocal()

    try:
        user = db.execute(select(User).where(User.email == email)).scalar_one_or_none()
        if user is None:
            print(f"[-] user not found: {email}", file=sys.stderr)
            return 1

        if user.is_admin:
            print(f"[=] {email} is already admin (id={user.id})")
            return 0

        user.is_admin = True
        db.commit()
        print(f"[+] {email} is now admin (id={user.id})")
        return 0
    finally:
        db.close()

if __name__ == "__main__":
    sys.exit(main())
