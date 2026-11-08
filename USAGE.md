# Запуск и использование Vault

Практические инструкции для локальной разработки и тестовых интеграций.
Краткий обзор проекта находится в [README.md](README.md), устройство компонентов
и OAuth-потока — в [ARCHITECTURE.md](ARCHITECTURE.md).

## 1. Подготовить окружение

Установите зависимости в виртуальное окружение:

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.txt
```

Запустите PostgreSQL и Redis. Значения подключения должны соответствовать
`DATABASE_URL` и `REDIS_URL`. Для локальной разработки не открывайте Redis и базу
данных в недоверенную сеть.

Создайте в корне проекта файл `.env` со следующими обязательными значениями:

```dotenv
DATABASE_URL=postgresql+psycopg2://vault:<DB_PASSWORD>@127.0.0.1:5432/vault_db
PASSWORD_PEPPER=<случайное_значение_не_короче_32_символов>
SESSION_SECRET=<отдельное_случайное_значение_не_короче_32_символов>
```

Все значения в угловых скобках — заполнители: замените их своими значениями,
не копируйте буквально. Сгенерируйте `PASSWORD_PEPPER` и `SESSION_SECRET`
независимо друг от друга командой:

```bash
python -c "import secrets; print(secrets.token_urlsafe(48))"
```

Не добавляйте `.env` в git и не передавайте реальные секреты через сообщения,
логи или снимки экрана. Остальные параметры конфигурации, включая `REDIS_URL`,
`ISSUER` и сроки действия, имеют значения по умолчанию; полный список приведён
в [ARCHITECTURE.md](ARCHITECTURE.md).

Создайте RSA-ключи и примените миграции:

```bash
python scripts/gen_keys.py
alembic upgrade head
```

`keys/rsa_private.pem` — приватный ключ, необходимый для подписи токенов.
Храните его с ограниченными правами доступа и не публикуйте. Запустите сервер:

```bash
python run.py
```

По умолчанию он доступен только на `127.0.0.1:8000`. Проверьте состояние и
документацию API:

```bash
curl http://127.0.0.1:8000/health
```

Swagger UI: `http://127.0.0.1:8000/docs`.

## 2. Зарегистрировать пользователя и администратора

Создать пользователя можно через SSR-форму `/web/register` или REST API:

```bash
curl -X POST http://127.0.0.1:8000/auth/register \
  -H 'Content-Type: application/json' \
  -d '{"email":"<USER_EMAIL>","password":"<STRONG_USER_PASSWORD>"}'
```

Поля в примере — заполнители, не реальные учётные данные. Для локального
ручного тестирования замените их; не используйте рабочие пароли в командной
строке или истории оболочки.

После регистрации назначить пользователю права администратора можно локально
на машине с настроенным `.env`:

```bash
python scripts/make_admin.py <USER_EMAIL>
```

Скрипт меняет запись в базе данных; передавайте адрес уже зарегистрированного
пользователя.

## 3. Создать OAuth-клиента

Администратор может создать клиента в `/web/admin/clients/new` или через
GraphQL mutation `createClient`. Для GraphQL используйте Bearer access-токен
администратора, полученный через `POST /auth/login`. Не публикуйте этот токен.
GraphQL endpoint — `/graphql/`.

Поля клиента включают `name`, `isConfidential`, `scopes`, `grantTypes` и
`redirectUris`. Разрешены scopes `openid`, `profile`, `email`,
`offline_access`; grant types: `authorization_code`, `refresh_token`, `password`,
`client_credentials`. Для `authorization_code` задайте callback URL. В
разработке URI должен в точности совпадать с передаваемым `redirect_uri`.

Mutation возвращает `clientId` и для конфиденциального клиента — `clientSecret`.
Сохраните секрет безопасно в момент создания: повторно показать его нельзя.
Публичный клиент не имеет секрета; для него используйте PKCE. Идентификатор
`clientId` из результата — это значение `client_id` для OAuth-запросов.

## 4. Пройти Authorization Code с PKCE

Этот поток выполняется через браузер, поскольку `/oauth/authorize` использует
веб-сессию Vault. Войдите в Vault, затем откройте URL авторизации с параметрами:

```text
http://127.0.0.1:8000/oauth/authorize?response_type=code&client_id=<CLIENT_ID>&redirect_uri=<URL_ENCODED_REGISTERED_REDIRECT_URI>&scope=openid%20email&state=<RANDOM_STATE>&code_challenge=<PKCE_S256_CHALLENGE>&code_challenge_method=S256
```

Замените каждый `<...>` заполнителем, сгенерированным для вашей локальной
регистрации/сессии. `state` должен быть случайным и проверяться клиентом при
callback. Создайте случайный PKCE `code_verifier` и передайте его приложению
клиента; `code_challenge` должен быть Base64URL(SHA-256(`code_verifier`).
Сохраняйте verifier и state на стороне клиента до callback.

После входа и подтверждения согласия Vault перенаправит браузер на
зарегистрированный callback с `code` и исходным `state`. Клиент должен сверить
`state`, а затем обменять код:

```bash
curl -X POST http://127.0.0.1:8000/oauth/token \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  --data-urlencode 'grant_type=authorization_code' \
  --data-urlencode 'client_id=<CLIENT_ID>' \
  --data-urlencode 'code=<AUTHORIZATION_CODE>' \
  --data-urlencode 'redirect_uri=<REGISTERED_REDIRECT_URI>' \
  --data-urlencode 'code_verifier=<ORIGINAL_PKCE_VERIFIER>'
```

Для конфиденциального клиента дополнительно передайте `client_secret` через
`--data-urlencode`, либо используйте настроенную HTTP Basic-аутентификацию
клиента. Для публичного клиента секрета нет. Код одноразовый и действует
ограниченное время; неверный verifier или повторный обмен завершается ошибкой.

## 5. Другие grant types и OIDC endpoints

### `client_credentials`

Только для конфиденциального клиента. Параметры передаются как
`application/x-www-form-urlencoded` на `POST /oauth/token`:

```text
grant_type=client_credentials
client_id=<CLIENT_ID>
client_secret=<CLIENT_SECRET>
scope=<SPACE_SEPARATED_SCOPES>
```

Секрет включён здесь только как явно обозначенный заполнитель. Этот поток не
аутентифицирует пользователя; токен не следует интерпретировать как пользовательский.

### `password`

Устаревший grant для учебной совместимости: передаются `grant_type=password`,
`client_id`, `username`, `password` и необязательный `scope`; конфиденциальный
клиент также передаёт `client_secret`. Для новых интеграций используйте
Authorization Code с PKCE.

### `refresh_token`

Передайте `grant_type=refresh_token`, `client_id`, `refresh_token` и, для
конфиденциального клиента, `client_secret`. При успешном обмене сервер возвращает
новый refresh-токен. Использованный токен нельзя применять повторно: повтор
запускает обнаружение повторного использования и отзыв соответствующего семейства.

### UserInfo, отзыв и интроспекция

- `GET /oauth/userinfo` — отправьте `Authorization: Bearer <ACCESS_TOKEN>`.
  Ответ зависит от scopes; endpoint предназначен для пользовательского токена.
- `POST /oauth/revoke` — передайте `token`, необязательный
  `token_type_hint`, `client_id` и секрет конфиденциального клиента. Endpoint
  отвечает без раскрытия, был ли токен активен.
- `POST /oauth/introspect` — передайте те же параметры, чтобы получить состояние
  токена. В текущей реализации активность токена раскрывается только
  аутентифицированному конфиденциальному клиенту; публичный клиент получает
  `{"active": false}`. Для обоих POST используется
  `Content-Type: application/x-www-form-urlencoded`.
- `GET /.well-known/openid-configuration` и
  `GET /.well-known/jwks.json` публикуют OIDC Discovery и открытые ключи.

Не вставляйте настоящие токены или секреты в примеры, общие терминалы, CI-логи
или документацию.

## 6. Веб-интерфейс и тестирование

- `/web/login`, `/web/register` — вход и регистрация.
- `/web/account`, `/web/account/sessions`, `/web/account/security` — кабинет,
  активные веб-сессии и смена пароля.
- `/web/consent` — подтверждение или отказ в запрошенном доступе OAuth.
- `/web/admin` — административная панель; для доступа требуется роль администратора.
- `/graphql/` — API; административные поля требуют Bearer-токен администратора.

Формы, изменяющие состояние, защищены CSRF-проверкой. Не отключайте её для
удобства тестирования.

Запустить тестовый набор:

```bash
pytest
```

Проверка из `examples/check_oauth.py` предназначена для работающего экземпляра
и предварительно настроенного OAuth-клиента. Для неё требуется отдельно
подготовить регистрацию и конфигурацию; тестовые данные не являются
производственными учётными данными.
