# CI/CD и проверки безопасности (v5)

В репозитории два равноправных CI:

- **GitLab** — `.gitlab-ci.yml` в корне. Рассчитан на форк во внутренний GitLab:
  из него собирается и публикуется образ для деплоя.
- **GitHub Actions** — `.github/workflows/v5-tests.yml` (тесты) и
  `.github/workflows/v5-security.yml` (безопасность) для публичного репозитория.

Оба прогоняют одни и те же проверки: SAST, поиск секретов, аудит зависимостей,
сканирование образа и DAST. Ниже описан GitLab-пайплайн, отличия GitHub
перечислены в конце.

## Стадии GitLab-пайплайна

```
verify → test (security) → build → scan → dast → publish
```

| Стадия | Джоба | Что делает | Блокирует? |
|---|---|---|---|
| verify | `verify` | `pip install -e ./v5[dev]`, `ruff check v5`, `pytest` (из `v5/`), `scripts/dump_tool_table.py --check` | **да** |
| test | `semgrep-sast` | SAST по шаблону `Security/SAST.gitlab-ci.yml` (Semgrep, правила для Python) | нет (отчёт) |
| test | `secret_detection` | поиск секретов по шаблону `Security/Secret-Detection.gitlab-ci.yml` | нет (отчёт) |
| test | `bandit` | `bandit -r v5/ewsmcp -ll`: severity medium и выше; полный JSON-отчёт в артефакте | **да** |
| test | `dependency_audit` | `pip-audit --strict` по runtime-зависимостям v5, JSON в артефакте | нет (`allow_failure`) |
| build | `build_image` | `docker build v5`, push `$CI_REGISTRY_IMAGE:<short-sha>` | **да** |
| scan | `container_scan` | Trivy по собранному образу: HIGH/CRITICAL с `--ignore-unfixed`, JSON в артефакте | **да** |
| dast | `dast_smoke` | `v5/scripts/dast_smoke.sh` против эфемерного контейнера | **да** |
| dast | `dast_baseline` | ZAP baseline (`zap-baseline.py -I`), отчёты HTML/JSON/MD в артефакте | нет (`allow_failure`) |
| publish | `publish_image` | на default-ветке → `:latest`, на теге → `:<tag>` | — |

`publish_image` запускается только на default-ветке (обычно `main`) и на тегах.
Он не пересобирает образ, а перетегирует тот же SHA-образ, который прошёл
Trivy-гейт и `dast_smoke`. Деплой тянет `:latest` или `:<tag>`.

Шаблонные джобы SAST и Secret Detection сами пайплайн не валят: находки лежат в
артефактах. Дашборд уязвимостей есть только в GitLab Ultimate, сами джобы и отчёты
работают и на free-tier. Legacy-код v1–v4 в корне репозитория (`src/`, `examples/`)
не деплоится и исключён из SAST через `SAST_EXCLUDED_PATHS`.

### DAST: что именно проверяется

Сервер запускается из собранного образа в OAuth-режиме. Exchange указан как
заведомо несуществующий адрес, поэтому реальный ящик не нужен:

```
EWS_SERVER_URL=https://exchange.invalid/EWS/Exchange.asmx   # .invalid — RFC 2606
MCP_OAUTH_ENABLED=true                                      # EWS_EMAIL не нужен
MCP_PUBLIC_URL=https://<имя-контейнера>                     # issuer в метаданных
DATA_DIR=/data
```

`MCP_PUBLIC_URL` указан с `https://`, потому что конфиг допускает `http://` только
для loopback. Так же сервер работает и в проде, за TLS-прокси. Само значение
попадает только в OAuth-метаданные, запросы идут по `http://<контейнер>:8000`.

`dast_smoke.sh` проверяет (POSIX sh, только curl):

1. `GET /livez` → 200;
2. `GET /.well-known/oauth-authorization-server` → 200, JSON с `issuer` и `token_endpoint`;
3. `GET /.well-known/oauth-protected-resource/mcp` → 200, JSON с `resource` и `authorization_servers`;
4. `POST /mcp` без токена → 401 и заголовок `WWW-Authenticate` с `resource_metadata=`;
5. `POST /mcp` с поддельным Bearer-токеном → 401.

После него ZAP baseline пассивно обходит ту же поверхность. Его предупреждения
(например, об отсутствии security-заголовков) информационные.

## Переменные CI/CD

Задаются в **Settings → CI/CD → Variables** проекта или группы. Все необязательны:
с пустыми значениями пайплайн ходит напрямую в Docker Hub, ghcr.io и PyPI.

| Переменная | Назначение | Пример |
|---|---|---|
| `RUNNER_TAG` | тег раннера для всех джоб (по умолчанию `local-docker`) | `docker` |
| `MIRROR_DOCKERHUB` | префикс зеркала Docker Hub **со слешем на конце**. Через него тянутся python, docker, trivy, curl, а также базовый образ Dockerfile (build-arg `REGISTRY`) | `mirror.example.com/dockerhub/` |
| `MIRROR_GHCRIO` | префикс зеркала ghcr.io **со слешем на конце** (образ ZAP) | `mirror.example.com/ghcr/` |
| `PIP_INDEX_URL` | зеркало PyPI. Его читают pip в джобах verify/test и сборка образа (build-arg, только builder-stage) | `https://pypi.example.com/simple` |
| `TRIVY_DB_REPOSITORY` | зеркало БД уязвимостей Trivy, если ghcr.io/mirror.gcr.io недоступны | `mirror.example.com/ghcr/aquasecurity/trivy-db:2` |
| `TRIVY_JAVA_DB_REPOSITORY` | то же для Java-БД (для Python-образа обычно не требуется) | — |

`CI_REGISTRY*`, `CI_COMMIT_*` и `CI_DEFAULT_BRANCH` GitLab выставляет сам.

Версии внешних образов заданы в блоке `variables:` в начале `.gitlab-ci.yml`:
`PYTHON_IMAGE`, `DOCKER_IMAGE`, `DOCKER_DIND_IMAGE`, `TRIVY_IMAGE`, `ZAP_IMAGE`,
`CURL_IMAGE`. Для максимальной воспроизводимости их можно закрепить по digest
(`образ@sha256:…`).

### Требования к раннеру

- Docker-executor. Для build/scan/dast/publish нужен privileged-раннер
  (`docker:dind`). Сервис dind подключён с `alias: docker`, поэтому с зеркалом
  тоже работает.
- Если раннер отдаёт хостовый сокет вместо dind, уберите `services` и
  `DOCKER_TLS_CERTDIR` из шаблона `.docker` и смонтируйте `/var/run/docker.sock`.
  Имена DAST-сетей, контейнеров и томов уникальны на джобу (`$CI_JOB_ID`), так что
  общий демон допустим.
- Bind-mount из джоб-контейнера в dind не виден. Поэтому скрипт smoke передаётся в
  curl-контейнер через stdin, а отчёты ZAP выносятся из named volume через `docker cp`.

## Что блокирует, а что информационно

**Блокирует** (красный пайплайн, публикации нет): `verify`, `bandit` (medium+),
`build_image`, `container_scan` (Trivy HIGH/CRITICAL с доступным исправлением),
`dast_smoke`.

**Информационно**: `semgrep-sast`, `secret_detection`, `dependency_audit`
(новая advisory во внешней зависимости не должна стопорить деплой: исправленный
образ всё равно проходит Trivy), `dast_baseline` (ZAP).

Если bandit сработал ложно, глушите конкретное место в коде комментарием
`# nosec BXXX` с объяснением. Ослаблять гейт не нужно.

## Харднинг образа (`v5/Dockerfile`)

- база `python:3.13-slim` в обоих stage, префикс зеркала задаётся через `ARG REGISTRY`;
- в runtime выполняется `apt-get upgrade`: Trivy-гейт с `--ignore-unfixed` требует,
  чтобы доступные исправления ОС были применены;
- в runtime-образе нет pip: ни системного, ни в `/opt/venv`. Вендоренные в pip
  библиотеки (`pip/_vendor/vendor.txt`: urllib3, msgpack, setuptools) отстают от
  upstream-исправлений, и Trivy находит в них HIGH;
- непривилегированный пользователь `mcp`, том `/data`, `PYTHONDONTWRITEBYTECODE=1`,
  `HEALTHCHECK` по `/livez`, сборка проверяется импортом `python -c "import ewsmcp.main"`;
- `.dockerignore` не пускает в контекст `.env*`, `.venv`, `build/`, `*.egg-info`,
  тесты и документацию.

## Локальный запуск

Из корня репозитория, в виртуальном окружении с установленным `./v5[dev]`.

```sh
# bandit — тот же гейт, что в CI
pip install "bandit>=1.8,<2"
bandit -r v5/ewsmcp -ll

# pip-audit — только runtime-зависимости, в чистом venv
python -m venv /tmp/audit && /tmp/audit/bin/pip install ./v5
/tmp/audit/bin/pip freeze --exclude-editable | grep -iv '^ews-mcp' > /tmp/audit-req.txt
/tmp/audit/bin/pip install "pip-audit>=2.7,<3"
/tmp/audit/bin/pip-audit --strict --no-deps --disable-pip -r /tmp/audit-req.txt

# образ + Trivy
docker build -t ews-mcp:local v5
docker run --rm -v /var/run/docker.sock:/var/run/docker.sock aquasec/trivy:0.65.0 \
  image --scanners vuln --severity HIGH,CRITICAL --ignore-unfixed --exit-code 1 ews-mcp:local

# DAST smoke против локального контейнера (http допустим для loopback)
docker run -d --name ews-mcp-dast -p 8000:8000 \
  -e EWS_SERVER_URL=https://exchange.invalid/EWS/Exchange.asmx \
  -e MCP_OAUTH_ENABLED=true -e MCP_PUBLIC_URL=http://localhost:8000 \
  -e DATA_DIR=/data ews-mcp:local
sh v5/scripts/dast_smoke.sh http://localhost:8000
docker rm -f ews-mcp-dast
```

`dast_smoke.sh` принимает базовый URL первым аргументом или через `BASE_URL`.
Сначала он ждёт `/livez` до `SMOKE_WAIT_SECONDS` секунд (по умолчанию 60).
Код выхода 0 означает, что все проверки прошли, 1 — что хотя бы одна упала.

## Отличия GitHub Actions (`v5-security.yml`)

Запускается на push и PR, затрагивающих `v5/**`, раз в неделю по расписанию и
вручную.

- `bandit` — блокирует (medium+), JSON-артефакт;
- `pip-audit` — информационно (`continue-on-error`);
- `gitleaks` — CLI в контейнере (gitleaks-action v2 требует лицензию для
  организаций). Блокирует. Проверяются только коммиты текущего push/PR: в старой
  истории есть тестовые фикстуры, похожие на ключи. Новая ветка, расписание и ручной
  запуск сканируют дерево файлов. Вывод маскируется (`--redact`);
- `codeql` — Python, `security-extended`, только `v5/ewsmcp`. Для приватного форка
  на GitHub нужен GitHub Advanced Security;
- `image-scan` — тот же Trivy-гейт. Trivy запускается из закреплённого образа, а не
  через `trivy-action` с изменяемыми тегами;
- `dast` — тот же `dast_smoke.sh` (блокирует) и `zaproxy/action-baseline`
  (информационно, без создания issue). Порт пробрасывается на `localhost`,
  поэтому здесь `MCP_PUBLIC_URL=http://localhost:8000`.

`v5-tests.yml` (всё блокирует): ruff, pytest и сверка docs на Python 3.11/3.12/3.13,
boot-smoke, сборка образа.
