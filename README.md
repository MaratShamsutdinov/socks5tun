## Логирование UDP-трафика

По умолчанию приложение логирует весь UDP-трафик — как **разрешённый**, так и **заблокированный**.

- Разрешённые UDP-пакеты записываются в журнал уровня INFO с префиксом `[UDP-ALLOW]`. В сообщении указываются исходный адрес:порт клиента, адрес:порт назначения и размер переданных данных.
- Заблокированные UDP-пакеты записываются в журнал уровня WARNING с префиксом `[UDP-DENY ]`. В сообщении указываются исходный адрес:порт клиента, адрес:порт назначения и причина блокировки (например, `reason=deny_rule`).

Пример фрагмента журнала UDP-трафика:

```text
[UDP-ALLOW] 192.0.2.10:39522 → 8.8.8.8:53 len=42
[UDP-DENY ] 10.0.0.5:60234 → 192.168.0.1:80 reason=deny_rule
```

---

## Автосетап TUN/NAT

Если в конфигурационном файле (`config.json`) заданы параметры блоков:

```json
"tun": {
  "name": "tun0",
  "address": "10.8.0.1",
  "netmask": "255.255.255.0",
  "peer_address": "10.8.0.2",
  "mtu": 1500
},
"nat": {
  "out_iface": "eth0"
}
```

то при старте сервера **TUN‑интерфейс** и **NAT‑правила** будут настраиваться автоматически.

- Автосетап выполняется **только**, если процесс запущен с правами `root` (`UID 0`).
- В тестовом или CI‑окружении, где нет root‑доступа, авто‑сетап будет пропущен, и в логах появится предупреждение:

```text
[WARNING] Skipping TUN/NAT auto-setup: not running as root (UID != 0)
```

---

## Базовая настройка брандмауэра (UFW)

Для ограничения внешнего доступа рекомендуется разрешить только необходимые порты:

```bash
ufw default deny incoming
ufw default allow outgoing
ufw allow 22/tcp comment "SSH"
ufw allow 443/tcp comment "TLS (stunnel)"
ufw enable
```

- Это закроет все входящие соединения, кроме SSH и TLS‑порта, используемого stunnel.
- Порт SOCKS5 (например, 5000/tcp), на котором слушает Python‑сервер, при этом будет доступен **только локально** (127.0.0.1) и через stunnel.
- Если требуется прямой внешний доступ к SOCKS5, добавьте правило:

```bash
ufw allow 5000/tcp comment "SOCKS5 direct"
```

---

## Мини-бэкап конфигураций `/etc`

Для автоматического отслеживания и возможности отката изменений в системных конфигурациях `/etc` рекомендуется установить:

```bash
sudo apt install -y etckeeper
cd /etc
sudo etckeeper init
sudo etckeeper commit -m "Initial server snapshot"
```

Теперь изменения `/etc` будут отслеживаться с помощью Git. Это удобно при ручной настройке `ufw`, `ssh`, `resolv.conf`, и т.д.

---

## Потенциальное улучшение: базовая защита SSH

Для повышения безопасности SSH можно добавить отдельный файл настроек `/etc/ssh/sshd_config.d/hardening.conf`:

```conf
PermitRootLogin no
PasswordAuthentication no
ClientAliveInterval 300
ClientAliveCountMax 2
```

- **PermitRootLogin no** — запрет входа под root по SSH.
- **PasswordAuthentication no** — отключение входа по паролю (только по SSH-ключу).
- **ClientAliveInterval** и **ClientAliveCountMax** — автоматическое завершение сессий при отсутствии активности.

> ⚠️ Перед применением убедитесь, что у вас есть рабочая учётная запись с ключом SSH и правами `sudo`.
> Рекомендуется сначала протестировать вход в новой сессии, и только потом закрывать текущую.

## Потенциальное улучшение: максимальная изоляция `stunnel`

В будущем возможно реализовать запуск `stunnel` с усиленной безопасностью. Это актуально при открытом или публичном VPN-сервисе с несколькими пользователями.

### ✅ Отдельный системный пользователь

```bash
sudo adduser --system --group --no-create-home stunnel
sudo chown root:stunnel /etc/stunnel
sudo chmod 750 /etc/stunnel
sudo chown root:stunnel /etc/stunnel/stunnel.pem
sudo chmod 640 /etc/stunnel/stunnel.pem
```

### ✅ Вынос PID-файла в безопасное место

```ini
pid = /run/stunnel/stunnel.pid
```

### ✅ Создание каталога и прав на него

```bash
sudo mkdir -p /run/stunnel
sudo chown stunnel:stunnel /run/stunnel
```

### ✅ Выдача capability для портов < 1024

```bash
sudo setcap 'cap_net_bind_service=+ep' /usr/bin/stunnel
```

### ✅ Защита через systemd (в unit-файле)

```ini
NoNewPrivileges=true
ProtectSystem=full
ReadOnlyPaths=/etc/stunnel
```

### 🧱 (опционально) chroot

Если требуется полная изоляция файловой системы (FS), возможно использование `chroot` — но это требует ручной подготовки окружения (библиотек, /dev/null и т.п.).

> Эти меры изолируют `stunnel` от остальной системы, даже если произойдёт взлом или утечка ключей.

Применить изменения:

```bash
sudo systemctl restart ssh
```

---

## Обновление и управление сервисом SOCKS5TUN

Проект включает встроенную систему обновления и перезапуска через связку:

- `update_socks5tun` — исполняемый скрипт/модуль, отвечающий за загрузку, установку или замену кода проекта.
- `socks5tun-update.service` — вспомогательный systemd-сервис, выполняющий `update_socks5tun` перед запуском основного прокси.
- `socks5tun.service` — основной сервис, запускающий SOCKS5-прокси сервер.

### Схема запуска

1. При запуске `socks5tun.service` автоматически **выполняется `socks5tun-update.service`**, если он указан как `Requires` + `After` в `Unit`-блоке.
2. Только **после успешного завершения обновления** стартует основной сервер.

Такой подход гарантирует, что при перезапуске системы или сервиса будет использоваться **актуальная версия** кода.

### Вручную

Для ручного запуска без обновления:

```bash
sudo systemctl start socks5tun.service
```

Для запуска только обновления (без старта прокси):

```bash
sudo systemctl start socks5tun-update.service
```

Для выполнения обновления вручную (если `update_socks5tun` — исполняемый файл):

```bash
sudo /usr/local/bin/update_socks5tun
```

---

## Работа с systemd

После изменения `.service`‑файлов **не забудьте перезагрузить systemd**:

```bash
sudo systemctl daemon-reload
```

Перезапуск сервиса:

```bash
sudo systemctl restart socks5tun.service
```

Просмотр логов:

```bash
journalctl -u socks5tun.service -f
```

Если вы изменили только Python‑код (`*.py`) — `daemon-reload` **не требуется**, достаточно `restart`.

---

## Размещение файлов

- `update_socks5tun` должен быть исполняемым (`chmod +x`) и доступным в PATH или по абсолютному пути (например, `/usr/local/bin/`).
- Юнит‑файлы systemd обычно размещаются в `/etc/systemd/system/`:

```bash
/etc/systemd/system/socks5tun.service
/etc/systemd/system/socks5tun-update.service
```

Проверь, чтобы они были включены в автозагрузку:

```bash
sudo systemctl enable socks5tun.service
```

> Обновление не выполняется, если сервис запускается напрямую (`python run.py`) — только через systemd.
