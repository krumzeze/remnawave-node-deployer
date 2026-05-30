# remnawave-node-deployer

Сервис для автоматического подключения новых нод к панели
[Remnawave](https://github.com/remnawave/panel). Управление идёт через
Telegram-бота или веб-интерфейс: вы указываете доступ к серверу, а сервис сам
настраивает его и регистрирует как ноду в панели.

Вся ручная рутина — заход по SSH, базовая защита сервера, установка Docker,
разворот контейнера `remnanode`, регистрация в панели и проверка статуса —
выполняется автоматически в фоне.

## Возможности

- Подключение сервера по SSH с переводом на ключевую авторизацию.
- Базовый hardening: UFW, fail2ban, отключение входа по паролю.
- Установка Docker и разворот контейнера `remnanode` через Ansible.
- Регистрация ноды в панели Remnawave по API и ожидание статуса `online`.
- Два режима работы с панелью: подключение к уже существующей или разворот
  новой.
- Выбор способа доступа к серверу: логин с паролем (сервис сам переведёт на
  ключ) или собственный публичный ключ.
- Фоновая обработка задач с очередью и отслеживанием состояния.
- Хранение SSH-ключей и токенов панели в HashiCorp Vault.
- Аудит действий, выполненных на сервере.

## Архитектура

```
Telegram-бот ─┐
веб-интерфейс ┤  ставят задачу
              ▼
        Redis + arq  ──▶  воркер
                           ├─ SSH bootstrap (asyncssh)
                           ├─ Ansible: hardening + Docker
                           ├─ разворот remnanode (compose)
                           └─ опрос API панели до online
панель Remnawave ◀── CreateNode / статус
Vault            ◀── SSH-ключи и токены панелей
Postgres         ◀── ноды, панели, задачи, аудит
```

Каждая задача проходит через состояния:

```
queued → bootstrapping → provisioning → registering → online
                                          └─ failed / rolled_back
```

Необратимые действия выполняются осторожно: вход по паролю отключается только
после того, как доступ по ключу проверен и работает.

## Требования

- Docker и Docker Compose.
- Бот Telegram (токен от [@BotFather](https://t.me/BotFather)).
- Панель Remnawave версии `2.7.x` с доступом к API.
- Целевые серверы под управлением Ubuntu 22.04 или 24.04.

## Стек

Python (aiogram, FastAPI), asyncssh, ansible-runner, Remnawave Python SDK,
Redis + arq, HashiCorp Vault, PostgreSQL.

## Установка и запуск

```bash
git clone https://github.com/krumzeze/remnawave-node-deployer.git
cd remnawave-node-deployer
cp .env.example .env     # заполнить настройки
docker compose up -d
```

Поднимаются сервисы: бот, воркер, веб-интерфейс, PostgreSQL, Redis и Vault.

## Конфигурация

Настройки задаются через `.env` (шаблон — в `.env.example`):

| Переменная | Назначение |
|---|---|
| `BOT_TOKEN` | токен Telegram-бота |
| `POSTGRES_*` | подключение к PostgreSQL |
| `REDIS_*` | подключение к Redis |
| `VAULT_ADDR`, `VAULT_TOKEN` | доступ к Vault |
| `REMNAWAVE_PANEL_URL`, `REMNAWAVE_API_TOKEN` | доступ к панели |
| `WEB_HOST`, `WEB_PORT` | адрес веб-интерфейса |

## Структура репозитория

```
bot/            Telegram-бот: хендлеры и FSM-диалог добавления ноды
orchestrator/   оркестрация: state-машина, SSH bootstrap, клиент API, задачи
ansible/        плейбуки hardening и разворота ноды
db/             модели базы данных
secrets/        интеграция с Vault
web/            веб-интерфейс (FastAPI)
tests/          тесты
```

## Статус

Проект на стадии MVP: каркас собран, отдельные компоненты в разработке.
