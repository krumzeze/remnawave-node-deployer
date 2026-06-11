storage "file" {
  # /vault/file образ hashicorp/vault создаёт заранее с владельцем vault:vault,
  # поэтому сервер пишет туда без прав root и без отдельного chown.
  path = "/vault/file"
}

listener "tcp" {
  address     = "0.0.0.0:8200"
  tls_disable = 1
}

# Файловое хранилище переживает рестарт (в отличие от dev-режима, где всё было
# в памяти и токен панели/ключи нод терялись при перезапуске). mlock выключаем:
# контейнеру не выдаём CAP_IPC_LOCK, а данные и так лежат в томе.
disable_mlock = true
api_addr      = "http://vault:8200"
ui            = false
