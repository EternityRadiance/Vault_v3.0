# Vault — OAuth2/OIDC Provider + SSR Web UI

Сервис управления пользователями и OAuth-клиентами с веб-интерфейсом на SSR (Jinja2).
Реализует **OAuth2 (RFC 6749)** и **OpenID Connect** + полноценный сайт для пользователей
и администраторов.

## Что внутри

**OAuth2/OIDC**
- RS256-подписи JWT, публикация **JWKS**, OIDC Discovery.
- Grant-типы: `authorization_code` (PKCE S256), `refresh_token` (rotation + reuse detection),
  `password` (deprecated), `client_credentials`.
- Отзыв токенов (`/oauth/revoke`, RFC 7009), интроспекция (`/oauth/introspect`, RFC 7662).
- Blacklist access-токенов в Redis (TTL = остаток жизни).

**SSR Web UI**
- Jinja2-шаблоны: базовый layout, макросы, фильтры, автоэкранирование.
- Cookie-сессии (`WebSession` в БД + `SessionMiddleware`), **отдельные от OAuth-токенов**.
- CSRF-защита на всех POST-формах (double-submit, `secrets.compare_digest`).
- Личный кабинет: профиль, активные сессии, смена пароля.
- Админ-консоль: дашборд, пользователи, OAuth-клиенты, аудит с фильтрами и CSV-экспортом.
- Flash-сообщения, пагинация, live-поиск, тёмная тема (progressive enhancement).
- Consent screen для OAuth (см. `/web/consent`, лаб. 4 п. 9).

## Стек

- **FastAPI** — веб-фреймворк.
- **Ariadne** — schema-first GraphQL (для API-клиентов).
- **SQLAlchemy 2.x**, **Alembic** — ORM и миграции.
- **PostgreSQL** — БД (SQLite для тестов).
- **Redis** — blacklist access-токенов.
- **Jinja2** — SSR-шаблоны.
- **itsdangerous** (через Starlette `SessionMiddleware`) — подпись cookie-сессий.
- **python-jose**, **cryptography** — JWT (RS256).
- **argon2-cffi** — Argon2id для паролей и `client_secret`.
- **zxcvbn** — политика паролей.
- **user-agents** — парсинг User-Agent в списке сессий.

## Установка

```bash
git clone <URL_репозитория>
cd lab4_vault
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

## Настройка
1) Скопировать .env.example в .env:

```bash
cp .env.example .env
```


2) Сгенерировать PASSWORD_PEPPER:

```bash
python -c "import secrets; print(secrets.token_urlsafe(48))"
```

Вставить в .env PASSWORD_PEPPER.

3) Сгенерировать RSA-ключи:

```bash
python scripts/gen_keys.py
```

Создаст keys/rsa_private.pem и keys/rsa_public.pem. Приватный ключ не должен попадать в git — keys/ в .gitignore

4) Поднять PostgreSQL (если не установлен):

```bash
sudo apt install postgresql postgresql-contrib
sudo -u postgres psql -c "CREATE USER vault WITH PASSWORD '<password>';"
sudo -u postgres psql -c "CREATE DATABASE vault_db OWNER <username>;"
```


5) Поднять Redis (Docker):

```bash
docker run -d --name vault-redis --restart=always -p 6379:6379 redis:7-alpine
```


## Запуск
```bash
alembic upgrade head
python run.py
```

## Интерфейсы
1) Swagger UI - http://127.0.0.1:8000/docs
2) GraphQL Playground - http://127.0.0.1:8000/graphql/
3) Authorization endpoint (PKCE) - http://127.0.0.1:8000/oauth/authorize
4) Token endpoint (4 grant-типа) - http://127.0.0.1:8000/oauth/token
5) Отзыв токена - http://127.0.0.1:8000/oauth/revoke
6) Интроспекция - http://127.0.0.1:8000/oauth/introspect
7) OIDC Userinfo - http://127.0.0.1:8000/oauth/userinfo
8) OIDC Discovery - http://127.0.0.1:8000/.well-known/openid-configuration
9) JWKS - http://127.0.0.1:8000/.well-known/jwks.json

## SSR-веб-интерфейс
1) Вход(форма) - http://127.0.0.1:8000/web/login
2) Регистрация - http://127.0.0.1:8000/web/register
3) Личный кабинет(профиль) - http://127.0.0.1:8000/web/account
4) Активные сессии - http://127.0.0.1:8000/web/account/sessions
5) Смена пароля - http://127.0.0.1:8000/web/account/security
6) Админ-консоль: дашборд - http://127.0.0.1:8000/web/admin
7) Пользователи - http://127.0.0.1:8000/web/admin/users
8) Карточка пользователя - http://127.0.0.1:8000/web/admin/users/{id}
9) OAuth-клиенты - http://127.0.0.1:8000/web/admin/clients
10) Создать клиента - http://127.0.0.1:8000/web/admin/clients/new
11) Детали клиента - http://127.0.0.1:8000/web/admin/clients/{id}
12) Аудит с фильтрами - http://127.0.0.1:8000/web/admin/audit
13) Экспорт аудита в CSV - http://127.0.0.1:8000/web/admin/audit/export.csv
14) OAuth consent screen - http://127.0.0.1:8000/web/consent

## Назначение админа
После регистрации через /web/register выдай себе админку:
```bash
python scripts/make_admin.py user@example.com
```

## OAuth2/OIDC эндпоинты

| Метод | Путь | Назначение |
|-------|------|-----------|
| GET  | `/oauth/authorize` | Authorization endpoint (PKCE) |
| POST | `/oauth/token` | Token endpoint (4 grant-типа) |
| POST | `/oauth/revoke` | Отзыв токена (RFC 7009) |
| POST | `/oauth/introspect` | Интроспекция (RFC 7662) |
| GET  | `/oauth/userinfo` | OIDC UserInfo |
| GET  | `/.well-known/jwks.json` | JWKS |
| GET  | `/.well-known/openid-configuration` | OIDC Discovery |

## Поддерживаемые grant-типы

- `authorization_code` (с **PKCE S256** — обязателен для публичных клиентов).
- `refresh_token` (с **rotation** и **reuse detection**).
- `password` (deprecated в OAuth 2.1, но оставлен для first-party приложений).
- `client_credentials` (только для конфиденциальных клиентов).

## demo-RP
Демонстрационный OIDC-клиент (FastAPI + Jinja2).

```bash
uvicorn demo_rp.main:app --port 8001
```

## Тесты
```bash
python examples/check_oauth.py
pytest
```

## Безопасность

- **JWT (RS256)** для всех токенов: REST, GraphQL, OAuth2. Публичный ключ в JWKS.
- **Argon2id + pepper** для паролей и `client_secret`.
- **PKCE S256** для публичных клиентов.
- **Redirect URI** — точное совпадение.
- **Refresh rotation** + reuse detection -> отзыв всего семейства.
- **Blacklist access-токенов** в Redis (TTL = остаток жизни).
- **httponly cookies** для `/admin/` и `/account/` + CSRF-токен.
- `.env`, `keys/`, `*.db` — в `.gitignore`.