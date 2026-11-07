#!/usr/bin/env bash
set -e

PGPASSWORD=28067632
export PGPASSWORD

VAULT="http://127.0.0.1:8000"

echo "=== 1. Найти клиента с redirect_uris и grant_types=authorization_code ==="
CLIENT_ROW=$(psql -h 127.0.0.1 -U vault -d vault_db -t -A -F'|' -c "
    SELECT client_id, is_confidential, redirect_uris::text
    FROM oauth_clients
    WHERE is_active = true
      AND grant_types::text LIKE '%authorization_code%'
      AND jsonb_array_length(redirect_uris::jsonb) > 0
    LIMIT 1
")
echo "row: $CLIENT_ROW"

CLIENT_ID=$(echo "$CLIENT_ROW" | cut -d'|' -f1)
IS_CONF=$(echo "$CLIENT_ROW" | cut -d'|' -f2)
REDIRECTS=$(echo "$CLIENT_ROW" | cut -d'|' -f3)

echo "CLIENT_ID = $CLIENT_ID"
echo "IS_CONF   = $IS_CONF"
echo "REDIRECTS = $REDIRECTS"

REDIRECT_ORIGINAL=$(echo "$REDIRECTS" | python -c "import sys,json; a=json.loads(sys.stdin.read()); print(a[0])")
echo "REDIRECT_ORIGINAL = $REDIRECT_ORIGINAL"

echo
echo "=== 2. Логин пользователя ==="
LOGIN_JSON=$(curl -s -X POST "$VAULT/auth/login" \
  -H "Content-Type: application/json" \
  -d '{"email":"oauth-test@example.com","password":"some long password 12345"}')

USER_TOKEN=$(echo "$LOGIN_JSON" | python -c "import sys,json; print(json.load(sys.stdin).get('access_token',''))")
if [ -z "$USER_TOKEN" ]; then
  echo "!! login failed: $LOGIN_JSON"
  exit 1
fi
echo "user_token len = ${#USER_TOKEN}"

echo
echo "=== 3. GET /oauth/authorize ==="
RESP_HEADERS=$(mktemp)
RESP_BODY=$(mktemp)
curl -s -D "$RESP_HEADERS" -o "$RESP_BODY" \
  -G "$VAULT/oauth/authorize" \
  --data-urlencode "response_type=code" \
  --data-urlencode "client_id=$CLIENT_ID" \
  --data-urlencode "redirect_uri=$REDIRECT_ORIGINAL" \
  --data-urlencode "scope=openid email" \
  --data-urlencode "state=xyz" \
  --data-urlencode "code_challenge=E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM" \
  --data-urlencode "code_challenge_method=S256" \
  -H "Authorization: Bearer $USER_TOKEN"

echo "--- headers ---"
cat "$RESP_HEADERS"
echo "--- body ---"
cat "$RESP_BODY"
echo

LOCATION=$(grep -i "^location:" "$RESP_HEADERS" | sed 's/^[Ll]ocation: //' | tr -d '\r\n')
echo "LOCATION = $LOCATION"

CODE=$(echo "$LOCATION" | python -c "
import sys, urllib.parse as u
q = u.urlparse(sys.stdin.read()).query
print(u.parse_qs(q).get('code', [''])[0])
")
echo "CODE = $CODE"

if [ -z "$CODE" ]; then
  echo "!! Не получили code — authorize не отработал"
  exit 2
fi

echo
echo "=== 4. Обмен с ПРАВИЛЬНЫМ redirect_uri ==="
curl -s -X POST "$VAULT/oauth/token" \
  -d "grant_type=authorization_code" \
  -d "client_id=$CLIENT_ID" \
  -d "code=$CODE" \
  -d "redirect_uri=$REDIRECT_ORIGINAL" \
  -d "code_verifier=dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk" \
  | python -m json.tool

echo
echo "=== 5. Получить второй code и обменять с ЧУЖИМ redirect_uri ==="
RESP_HEADERS=$(mktemp)
curl -s -D "$RESP_HEADERS" -o /dev/null \
  -G "$VAULT/oauth/authorize" \
  --data-urlencode "response_type=code" \
  --data-urlencode "client_id=$CLIENT_ID" \
  --data-urlencode "redirect_uri=$REDIRECT_ORIGINAL" \
  --data-urlencode "scope=openid email" \
  --data-urlencode "state=xyz2" \
  --data-urlencode "code_challenge=E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM" \
  --data-urlencode "code_challenge_method=S256" \
  -H "Authorization: Bearer $USER_TOKEN"

LOCATION=$(grep -i "^location:" "$RESP_HEADERS" | sed 's/^[Ll]ocation: //' | tr -d '\r\n')
CODE2=$(echo "$LOCATION" | python -c "
import sys, urllib.parse as u
q = u.urlparse(sys.stdin.read()).query
print(u.parse_qs(q).get('code', [''])[0])
")
echo "CODE2 = $CODE2"

curl -s -X POST "$VAULT/oauth/token" \
  -d "grant_type=authorization_code" \
  -d "client_id=$CLIENT_ID" \
  -d "code=$CODE2" \
  -d "redirect_uri=http://evil.example.com/cb" \
  -d "code_verifier=dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk" \
  | python -m json.tool

echo
echo "=== Ожидание ==="
echo "Шаг 4: 200 с access_token (правильный redirect_uri)"
echo "Шаг 5: 400 invalid_grant (НЕ 200!) если проверка redirect_uri есть"