# Многопользовательский режим (OAuth 2.1)

Один сервер обслуживает много пользователей. Каждый работает со **своим**
почтовым ящиком и со **своими** правами Exchange. Сервисной учётки и
impersonation нет. Пользователь добавляет в клиент только URL, логин
происходит в браузере.

## Как это устроено

```
MCP-клиент ──DCR + PKCE──► ews-mcp (сам себе OAuth-сервер)
   │                         │  /authorize → /login: логин и пароль Exchange
   │                         │  проверка реальным запросом в EWS
   │◄── access + refresh ────┘
   └── Bearer ──► /mcp ──► контекст пользователя ──► EWS под его учёткой
```

- **Discovery.** `/.well-known/oauth-authorization-server` (RFC 8414) и
  `/.well-known/oauth-protected-resource[/mcp]` (RFC 9728). Без токена
  `/mcp` отвечает `401` с `WWW-Authenticate: Bearer resource_metadata=…`.
- **Регистрация клиентов** — анонимная (`POST /register`, RFC 7591).
  Поддерживаются публичные (`none`) и конфиденциальные
  (`client_secret_post`) клиенты. Redirect URI разрешены только такие:
  - loopback (`http://127.0.0.1:*`, `http://localhost:*`);
  - точное совпадение со списком `MCP_OAUTH_ALLOWED_REDIRECT_URIS`.
- **Логин.** На `/login` показываются имя клиента и адрес, куда вернётся
  пользователь. Нужно явно поставить галочку согласия. Пароль
  проверяется в Exchange (ResolveNames + GetFolder). Можно вводить
  UPN, SMTP или `DOMAIN\user`.
- **Токены.** Это непрозрачные строки `ewsat_…` и `ewsrt_…`:
  - access по умолчанию живёт 1 час, refresh — 30 дней;
  - при refresh выдаётся новая пара, а старые access и refresh
    аннулируются.
- **Хранение.** В `DATA_DIR/oauth.db` (SQLite) лежат только `sha256(токена)`
  и пароль, зашифрованный AES-256-GCM ключом `HKDF(токен)`. Самого токена
  сервер не хранит, поэтому утечка базы без токенов ящиков не открывает.
- **Смена пароля или блокировка в AD.** При первом же `401` от Exchange
  отзываются все гранты пользователя. Клиент заново проводит логин в
  браузере, а не долбит AD повторами, которые ведут к блокировке.
- **Защита формы.** Попытки входа ограничены: 5 за 15 минут на один логин
  и 20 за 15 минут на один IP. `/register` — 20 в час на IP. Тексты ошибок
  общие. Страница запрещает фреймы и кэширование.
- **Изоляция пользователей.** У каждого пользователя свои сессия EWS, пул
  потоков, алиасы id, лимит отправок и привязка confirm-токенов. Журнал
  аудита общий, в записях есть поле `user`. Кэш-зеркало почты и
  семантический индекс в этом режиме выключены, `get_attachment
  mode=save` запрещён: на общем сервере не должна копиться чужая почта.

## Конфигурация

| Переменная | Назначение | По умолчанию |
|---|---|---|
| `EWS_SERVER_URL` | EWS-эндпоинт, `https://mail.example.com/EWS/Exchange.asmx` | — (обязательно) |
| `MCP_TRANSPORT` | `http` | `stdio` |
| `MCP_HOST` / `MCP_PORT` | адрес прослушивания | `127.0.0.1` / `8000` |
| `MCP_OAUTH_ENABLED` | включить многопользовательский режим | `false` |
| `MCP_PUBLIC_URL` | внешний origin (issuer), только `https://` без пути | — (обязательно) |
| `MCP_OAUTH_ALLOWED_REDIRECT_URIS` | внешние redirect URI через запятую | пусто |
| `MCP_OAUTH_ACCESS_TTL_SECONDS` | время жизни access-токена | `3600` |
| `MCP_OAUTH_REFRESH_TTL_SECONDS` | время жизни refresh-токена | `2592000` |
| `MCP_FORWARDED_ALLOW_IPS` | адреса прокси, которым верим в `X-Forwarded-For` | `127.0.0.1` |
| `EWS_USER_IDLE_SECONDS` | через сколько закрыть простаивающую сессию EWS | `1800` |
| `EWS_MAX_USERS` | максимум живых сессий (LRU) | `200` |
| `MCP_API_KEY` | ключ оператора для `/metrics`; без него `/metrics` отвечает 404 | — |
| `EWS_CAPABILITY_TIER` | `read` / `draft` / `full` | `draft` |
| `SEND_ENABLED` | аварийный выключатель отправки | `false` |
| `EWS_TZ` | часовой пояс, например `Europe/Moscow` | зона хоста |
| `DATA_DIR` | volume для `oauth.db`, аудита и алиасов | `~/.ewsmcp` |

`EWS_EMAIL`, `EWS_USERNAME` и `EWS_PASSWORD` в этом режиме **не задаются**.

Какие инструменты кому разрешать, решает сам пользователь в своём
клиенте. Сервер отдаёт всё, что позволяет `EWS_CAPABILITY_TIER`, и
помечает каждый инструмент аннотациями `readOnlyHint` /
`destructiveHint`. Отправка и удаление в любом случае идут через
двухфазное подтверждение. Чтобы инструменты отправки были доступны, нужны
`EWS_CAPABILITY_TIER=full` и `SEND_ENABLED=true`. `SEND_ENABLED=false`
остаётся аварийным выключателем оператора.

Масштабирование: **одна реплика**. `oauth.db` — это SQLite на volume, а
сессии пользователей живут в памяти процесса. MCP-транспорт работает без
состояния (stateless), поэтому sticky-сессии не нужны.

## Развёртывание

### Контейнер (podman quadlet)

`/etc/containers/systemd/ews-mcp.container`:

```ini
[Unit]
Description=ews-mcp (multi-user)

[Container]
# Точный неизменяемый тег (релиз или main-<sha>), никогда не :latest
Image=registry.example.com/group/ews-mcp:v4.5.0a1
PublishPort=127.0.0.1:8010:8000
Volume=ews-mcp-data:/data
Environment=MCP_OAUTH_ENABLED=true
Environment=MCP_PUBLIC_URL=https://mcp-mail.example.com
Environment=MCP_OAUTH_ALLOWED_REDIRECT_URIS=https://claude.ai/api/mcp/auth_callback
Environment=EWS_SERVER_URL=https://mail.example.com/EWS/Exchange.asmx
Environment=EWS_TZ=Europe/Moscow
Environment=EWS_CAPABILITY_TIER=full
Environment=SEND_ENABLED=true
# Порт опубликован только на 127.0.0.1, значит до контейнера дойдёт
# только локальный nginx. Поэтому можно верить X-Forwarded-For от любого
# источника, каким бы его ни увидел контейнер.
Environment=MCP_FORWARDED_ALLOW_IPS=*
EnvironmentFile=-/etc/ews-mcp/secret.env

[Service]
Restart=always

[Install]
WantedBy=multi-user.target
```

В `secret.env` (режим `0600`) кладётся `MCP_API_KEY`, если нужен
`/metrics`.

### nginx

```nginx
server {
    listen 443 ssl http2;
    server_name mcp-mail.example.com;
    # ssl_certificate ...;

    # Снаружи нужны только OAuth и MCP
    location ~ ^/(mcp|authorize|token|register|revoke|login|\.well-known/) {
        proxy_pass http://127.0.0.1:8010;
        proxy_set_header Host $host;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_buffering off;            # SSE-ответы /mcp
        proxy_read_timeout 3600s;
        client_max_body_size 2m;
    }
    location = /livez { proxy_pass http://127.0.0.1:8010; }
    location / { return 404; }          # /metrics, /api/*, /openapi.json — только изнутри
}
```

Коннектор claude.ai ходит из облака Anthropic. Значит, `/mcp` и OAuth-пути
должны быть доступны из интернета, а
`https://claude.ai/api/mcp/auth_callback` должен быть в
`MCP_OAUTH_ALLOWED_REDIRECT_URIS`. Для пилота только с Claude Code и Codex
хватит внутреннего контура или SSH-туннеля: их redirect URI на loopback
разрешены всегда.

## Подключение пользователей

URL сервера: `https://mcp-mail.example.com/mcp`. Заголовки и токены вручную
не нужны.

| Клиент | Добавить | Залогиниться |
|---|---|---|
| Claude Code | `claude mcp add --transport http exchange https://mcp-mail.example.com/mcp` | `/mcp` → exchange → Authenticate |
| Codex | `codex mcp add exchange --url https://mcp-mail.example.com/mcp` | `codex mcp login exchange` |
| claude.ai | Settings → Connectors → Add custom connector → URL | кнопка Connect |

В браузере откроется форма. Туда вводится обычный логин Exchange (почта
или `DOMAIN\user`) и пароль, затем ставится галочка согласия. Когда
истекает refresh-токен (30 дней) или меняется пароль, клиент сам
попросит залогиниться заново.

## Эксплуатация

- **Отозвать доступ пользователя.** Удалите его строки:
  `sqlite3 /data/oauth.db "DELETE FROM grants WHERE subject='user@example.com'"`.
  Ещё проще сменить пароль в AD: первый же запрос получит `401`, и сервер
  сам отзовёт все гранты.
- **Отозвать у всех.** Остановите контейнер, удалите `oauth.db` и
  запустите заново. Всем придётся залогиниться повторно.
- **Аудит.** `DATA_DIR/audit/audit-YYYYMMDD.jsonl`, цепочка хэшей,
  поле `user`. Проверка — `python scripts/verify_audit_chain.py`.
- **Логи.** Неудачный вход пишется на уровне WARNING вместе с причиной
  (`auth_failed`, `upstream_unavailable` и т.д.). Пароли и токены в логи
  не попадают.
- **Здоровье.** `/livez` (процесс жив), `/readyz` (поле `users` — число
  живых сессий), `/metrics` с `MCP_API_KEY`.
- **Бэкап.** Volume с `oauth.db` бэкапить можно, без токенов он ящиков не
  открывает. Если его потерять, пользователям просто придётся
  залогиниться заново.

## Ограничения

- `/revoke` из SDK аутентифицирует клиента, поэтому работает только для
  конфиденциальных клиентов. У публичных токены просто истекают.
- Пароль хранится на сервере. Он зашифрован, расшифровать его можно только
  предъявленным токеном, но в памяти процесса он открыт, пока жива сессия
  пользователя. Это цена отказа от сервисной учётки и impersonation на
  Exchange без Modern Auth. Если на Exchange включат Modern Auth (Hybrid
  или ADFS для EWS), шифрованный пароль можно будет заменить
  upstream-токеном. Остальные слои от этого не меняются.
