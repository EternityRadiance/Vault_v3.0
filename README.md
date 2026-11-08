# Vault — OAuth 2.0 / OpenID Connect

Vault — учебный монолитный сервис на FastAPI: OAuth 2.0/OIDC-провайдер,
REST- и GraphQL API, а также серверный веб-интерфейс для пользователей и
администраторов. Проект предназначен для локального запуска и изучения; перед
публикацией в интернете требуется отдельная проверка и настройка безопасности.

## Возможности

- OAuth 2.0: `authorization_code` с PKCE, `refresh_token`,
  `client_credentials` и оставленный для совместимости `password`.
- OIDC: ID-токены RS256, UserInfo, Discovery и JWKS.
- Отзыв и интроспекция токенов; обнаружение повторного использования refresh-токена.
- REST API для регистрации и входа, GraphQL API для административных операций.
- SSR-интерфейс на Jinja2: регистрация и вход, кабинет, OAuth consent, управление
  клиентами и пользователями, аудит.
- PostgreSQL для постоянных данных; Redis для blacklist access-токенов и запросов
  согласия.

## Требования и запуск

Нужны Python 3.10+ (используйте версию, совместимую с установленными
зависимостями), PostgreSQL и Redis. Подготовьте виртуальное окружение и установите
зависимости:

```bash
git clone <URL-репозитория>
cd <каталог-проекта>
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.txt
```

Создайте `.env` в корне проекта. Обязательные значения:

```dotenv
DATABASE_URL=postgresql+psycopg2://vault:<DB_PASSWORD>@127.0.0.1:5432/vault_db
PASSWORD_PEPPER=<случайное_значение_не_короче_32_символов>
SESSION_SECRET=<отдельное_случайное_значение_не_короче_32_символов>
```

Замените все значения в угловых скобках своими; это обозначения, а не готовые
учётные данные. Сгенерируйте два независимых секрета локально, не добавляйте их в
репозиторий и не отправляйте в логи:

```bash
python -c "import secrets; print(secrets.token_urlsafe(48))"
```

Выполните эту команду отдельно для `PASSWORD_PEPPER` и `SESSION_SECRET`.
Приватный RSA-ключ создаётся отдельно:

```bash
python scripts/gen_keys.py
```

Скрипт сохраняет ключи в `keys/`; не публикуйте и не пересылайте
`keys/rsa_private.pem`. Убедитесь, что PostgreSQL и Redis доступны по адресам из
конфигурации (`DATABASE_URL` и `REDIS_URL`; Redis по умолчанию —
`redis://localhost:6379/0`). Примените миграции и запустите приложение:

```bash
alembic upgrade head
python run.py
```

Сервер разработки слушает `127.0.0.1:8000`. Проверка готовности:

```bash
curl http://127.0.0.1:8000/health
```

Подробная конфигурация и примеры OAuth-запросов приведены в
[инструкции по запуску и использованию](USAGE.md); описание компонентов и
потоков — в [архитектуре](ARCHITECTURE.md).

## Основные адреса

| Назначение | Метод и путь |
|---|---|
| Проверка состояния | `GET /health` |
| REST-регистрация и вход | `POST /auth/register`, `POST /auth/login` |
| Данные текущего пользователя | `GET /auth/me` |
| GraphQL | `/graphql/` |
| Авторизация и согласие OAuth | `GET /oauth/authorize`, `/web/consent` |
| Обмен кода или токена | `POST /oauth/token` |
| Отзыв и интроспекция | `POST /oauth/revoke`, `POST /oauth/introspect` |
| OIDC UserInfo | `GET /oauth/userinfo` |
| Discovery и ключи | `GET /.well-known/openid-configuration`, `GET /.well-known/jwks.json` |
| SSR-интерфейс | `/web/login`, `/web/register`, `/web/account` |
| Консоль администратора | `/web/admin` |

Интерфейс Swagger доступен по `/docs`. OAuth-адрес `/oauth/authorize` использует
веб-сессию и перенаправляет пользователя на вход и страницу согласия; это не
endpoint для Bearer-аутентификации. Точные примеры и ограничения описаны в
[USAGE.md](USAGE.md).

## Тесты

```bash
pytest
```

`examples/check_oauth.py` — отдельный сценарий проверки работающего сервера,
а не замена тестового набора. В его настройках должны быть указаны актуальные
адреса и зарегистрированный клиент; не помещайте секреты в репозиторий.

## Важные замечания по безопасности

- Не используйте демонстрационные настройки для реального развертывания.
  Настройте TLS, секреты и сетевой доступ к PostgreSQL/Redis; не публикуйте Redis
  без аутентификации в недоверенную сеть.
- `keys/rsa_private.pem`, `.env`, пароли, access/refresh-токены и секреты клиентов
  являются конфиденциальными. `client_secret` показывается при создании или
  ротации один раз.
- `password` grant устарел и оставлен для учебной/совместимой интеграции;
  предпочитайте `authorization_code` с PKCE.
- Cookie веб-сессии настроена как `HttpOnly`, `SameSite=Lax`; флаг `Secure`
  включается при `ENVIRONMENT=production`. Для защищенного развертывания
  используйте HTTPS.
