#!/bin/sh
# Запуск Vault в боевом режиме с файловым хранилищем + авто-распечатка.
#
# Зачем: в dev-режиме Vault держал секреты в памяти, и после перезапуска стека
# токен панели и SSH-ключи нод пропадали — бот «забывал» панель. Здесь хранилище
# на томе, поэтому секреты переживают рестарт. Цена авто-распечатки —
# unseal-ключ и root-токен лежат в том же томе (init.json, 0600). Для self-hosted
# single-tenant (ADR 0003), где сервер и так под контролем оператора, это
# осознанный компромис ради рестарта без ручной распечатки.
#
# Токен приложения: бот/воркер ходят в Vault под VAULT_TOKEN из .env. Этот же
# токен мы создаём здесь с фиксированным id и политикой только на KV-маунт —
# root-токен наружу не отдаём, он остаётся в init.json.
set -e

APP_TOKEN="${VAULT_TOKEN}"
KV_MOUNT="${VAULT_KV_MOUNT:-secret}"
INIT_FILE="/vault/file/init.json"

export VAULT_ADDR="http://127.0.0.1:8200"
unset VAULT_TOKEN  # на время bootstrap работаем под root из init.json

vault server -config=/vault/config/vault.hcl &
VAULT_PID=$!

# Ждём, пока API ответит (status: 0 — распечатан, 2 — запечатан, оба значат «жив»).
while true; do
  vault status >/dev/null 2>&1 && break
  [ "$?" = "2" ] && break
  sleep 1
done

# Инициализацию определяем по реальному состоянию Vault, а не по наличию файла:
# init -status даёт 0 (инициализирован) или 2 (нет). Опираться на файл нельзя —
# пустой/битый init.json от неудачного первого старта раньше приводил к пустому
# ключу и распечатке «с терминала» (file descriptor 0 is not a terminal).
if vault operator init -status >/dev/null 2>&1; then
  INITIALIZED=1
else
  INITIALIZED=0
fi

# Первый запуск — инициализация (1 доля ключа, порог 1: оператор один).
# Пишем через временный файл и mv: при сбое init.json не остаётся обрезанным.
if [ "$INITIALIZED" = "0" ]; then
  TMP="${INIT_FILE}.tmp"
  vault operator init -key-shares=1 -key-threshold=1 -format=json > "$TMP"
  mv "$TMP" "$INIT_FILE"
  chmod 600 "$INIT_FILE"
  echo "vault: initialised, keys saved to $INIT_FILE"
fi

# Vault инициализирован, но ключей нет (пустой/потерянный init.json) — распечатать
# нечем. Падаем с понятным сообщением вместо чтения ключа со stdin.
if [ ! -s "$INIT_FILE" ]; then
  echo "vault: FATAL — Vault инициализирован, но $INIT_FILE пуст или отсутствует;" \
       "unseal-ключ потерян. Восстановление: остановить стек и удалить том vaultdata" \
       "(секреты в нём будут потеряны), затем развернуть заново." >&2
  exit 1
fi

# vault operator init -format=json выводит отформатированный многострочный JSON
# (пробелы после двоеточий, массив на нескольких строках). Поэтому сначала
# схлопываем все пробелы и переводы строк, а потом достаём значения — иначе
# построчный grep ничего не находит и ключ выходит пустым.
JSON=$(tr -d ' \t\r\n' < "$INIT_FILE")
UNSEAL_KEY=$(printf '%s' "$JSON" | sed -n 's/.*"unseal_keys_b64":\["\([^"]*\)".*/\1/p')
ROOT_TOKEN=$(printf '%s' "$JSON" | sed -n 's/.*"root_token":"\([^"]*\)".*/\1/p')

if [ -z "$UNSEAL_KEY" ] || [ -z "$ROOT_TOKEN" ]; then
  echo "vault: FATAL — не удалось разобрать unseal-ключ или root-токен из $INIT_FILE" >&2
  exit 1
fi

# Распечатываем при каждом старте (после рестарта Vault снова запечатан).
if vault status 2>/dev/null | grep -q "Sealed.*true"; then
  vault operator unseal "$UNSEAL_KEY" >/dev/null
  echo "vault: unsealed"
fi

export VAULT_TOKEN="$ROOT_TOKEN"

# KV v2 на нужном пути (идемпотентно: если уже включён — игнорируем ошибку).
vault secrets enable -path="$KV_MOUNT" kv-v2 >/dev/null 2>&1 || true

# Политика приложения: доступ только к своему KV-маунту.
vault policy write deployer - >/dev/null <<EOF
path "${KV_MOUNT}/*" {
  capabilities = ["create", "read", "update", "delete", "list"]
}
path "${KV_MOUNT}/data/*" {
  capabilities = ["create", "read", "update", "delete", "list"]
}
EOF

# Токен приложения с фиксированным id из .env (если ещё не создан).
if [ -n "$APP_TOKEN" ] && ! vault token lookup "$APP_TOKEN" >/dev/null 2>&1; then
  vault token create -id="$APP_TOKEN" -policy=deployer -orphan -period=768h >/dev/null
  echo "vault: app token provisioned"
fi

echo "vault: ready"
wait "$VAULT_PID"
