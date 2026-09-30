# Работа 1 — Защищённый REST API с интеграцией в CI/CD

[![CI](https://github.com/tronget/REPO/actions/workflows/ci.yml/badge.svg)](https://github.com/OWNER/REPO/actions/workflows/ci.yml)

REST API на **Python / Flask** с аутентификацией по JWT, хранением паролей в
виде bcrypt-хэшей, защитой от SQL-инъекций и XSS, и pipeline'ом GitHub Actions,
в котором на каждый push и pull request запускаются SAST- и SCA-сканеры.

> **Замените `OWNER/REPO` в бейдже и в ссылках ниже на реальные значения после
> публикации репозитория на GitHub.**

---

## Содержание

1. [Стек](#стек)
2. [Быстрый старт](#быстрый-старт)
3. [Описание API](#описание-api)
4. [Реализованные меры защиты](#реализованные-меры-защиты)
5. [CI/CD pipeline с security-сканерами](#cicd-pipeline-с-security-сканерами)
6. [Скриншоты отчётов SAST/SCA](#скриншоты-отчётов-sastsca)
7. [Тестирование](#тестирование)
8. [Структура проекта](#структура-проекта)
9. [Переменные окружения](#переменные-окружения)
10. [Запуск в Docker](#запуск-в-docker)
11. [Известные ограничения и дальнейший план](#известные-ограничения-и-дальнейший-план)

---

## Стек

| Компонент | Выбор | Почему |
| --- | --- | --- |
| Язык / фреймворк | Python 3.9+ / Flask 3 | разрешён заданием |
| Менеджер пакетов | pip (`requirements.txt`) | разрешён заданием |
| БД | SQLite (по умолчанию), PostgreSQL через `DATABASE_URL` | простота учебного примера |
| ORM | SQLAlchemy 2.x | параметризованные запросы = защита от SQLi |
| Хэширование паролей | bcrypt | адаптивная функция с солью |
| Аутентификация | PyJWT (HS256) + собственный middleware | требование задания |
| Валидация | pydantic v2 | строгая allow-list-валидация входа |
| Rate limiting | Flask-Limiter | защита от подбора паролей |
| Тесты | pytest + pytest-cov | 189 тестов, покрытие 98% |
| CI | GitHub Actions | требование задания |
| **SAST** | **bandit** | требование задания |
| **SCA** | **pip-audit** + OWASP Dependency-Check | требование задания |

---

## Быстрый старт

```bash
git clone https://github.com/OWNER/REPO.git
cd REPO

# 1. Окружение и зависимости
python3 -m venv .venv
.venv/bin/python -m pip install --upgrade pip
.venv/bin/pip install -r requirements.txt -r requirements-dev.txt
#  то же самое одной командой:  make install

# 2. Запуск сервера
make run                       # http://127.0.0.1:8000
#  или:  .venv/bin/flask --app wsgi run --port 8000

# 3. Сквозная проверка API в другом терминале
./docs/curl-examples.sh
```

Скрипт `docs/curl-examples.sh` последовательно проверяет весь сценарий:
регистрация → повторная регистрация (409) → слабый пароль (422) → login →
**GET /api/data без токена (401)** → **с токеном (200)** → POST (201) →
SQLi-payload в поиске → GET по id → refresh → DELETE (204) → logout →
повтор с отозванным токеном (401). Любой неожиданный код ответа — ненулевой
выход.

Для Postman: импортируйте `docs/postman_collection.json` — после запроса
`Login` токены сохраняются в переменные коллекции автоматически.

---

## Описание API

Base URL: `http://127.0.0.1:8000`. Все ответы — `application/json`.
Полная спецификация с телами запросов и ответов: **[`docs/API.md`](docs/API.md)**.

| Метод | Путь | Auth | Назначение | Успех |
| --- | --- | --- | --- | --- |
| GET | `/health` | — | проба живости | 200 |
| POST | `/auth/register` | — | регистрация | 201 |
| **POST** | **`/auth/login`** | — | **п.1 задания** — логин, выдача JWT | 200 |
| POST | `/auth/refresh` | refresh JWT | обновление access-токена | 200 |
| POST | `/auth/logout` | access JWT | завершение сессии: отзыв access- **и** refresh-токена | 204 |
| GET | `/api/me` | access JWT | профиль текущего пользователя | 200 |
| **GET** | **`/api/data`** | access JWT | **п.2 задания** — список заметок, пагинация и поиск | 200 |
| **POST** | **`/api/data`** | access JWT | **п.3 задания (свой метод)** — создать заметку | 201 |
| GET | `/api/data/{id}` | access JWT | одна заметка (проверка владельца) | 200 |
| DELETE | `/api/data/{id}` | access JWT | удалить свою заметку | 204 |

Коды ошибок: `400` некорректный JSON, `401` нет/битый/истёкший/отозванный токен
или неверные учётные данные, `403` чужой ресурс, `404` не найдено,
`405` метод не разрешён, `409` логин занят, `413` тело больше 64 КБ,
`422` ошибка валидации, `429` превышен rate limit, `500` внутренняя ошибка.

Единый формат ошибки:

```json
{ "error": { "code": "unauthorized", "message": "Invalid credentials." } }
```

### Примеры вызовов

**Регистрация**

```bash
curl -s -X POST http://127.0.0.1:8000/auth/register \
  -H 'Content-Type: application/json' \
  -d '{"username":"alice","password":"Alice-Str0ng!Pass"}'
```

```json
{ "id": 1, "username": "alice", "created_at": "2026-09-05T10:48:23.542057+00:00" }
```

**Логин (п.1 задания)**

```bash
curl -s -X POST http://127.0.0.1:8000/auth/login \
  -H 'Content-Type: application/json' \
  -d '{"username":"alice","password":"Alice-Str0ng!Pass"}'
```

```json
{
  "token_type": "Bearer",
  "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9....",
  "refresh_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9....",
  "expires_in": 900,
  "user": { "id": 1, "username": "alice" }
}
```

**Получение данных без токена — доступ запрещён**

```bash
curl -s http://127.0.0.1:8000/api/data
```

```json
{ "error": { "code": "unauthorized", "message": "Authorization header is missing." } }
```

HTTP 401 + заголовок `WWW-Authenticate: Bearer`.

**Получение данных с токеном (п.2 задания)**

```bash
curl -s "http://127.0.0.1:8000/api/data?page=1&per_page=20" \
  -H "Authorization: Bearer ${ACCESS_TOKEN}"
```

```json
{ "items": [], "page": 1, "per_page": 20, "total": 0, "query": null }
```

**Создание заметки (п.3 задания) — XSS-payload возвращается экранированным**

```bash
curl -s -X POST http://127.0.0.1:8000/api/data \
  -H "Authorization: Bearer ${ACCESS_TOKEN}" \
  -H 'Content-Type: application/json' \
  -d '{"title":"<script>alert(1)</script>","content":"first note"}'
```

```json
{
  "id": 1,
  "owner_id": 1,
  "title": "&lt;script&gt;alert(1)&lt;/script&gt;",
  "content": "first note",
  "created_at": "2026-09-05T10:48:23.589476+00:00",
  "updated_at": "2026-09-05T10:48:23.589477+00:00"
}
```

---

## Реализованные меры защиты

### 1. Защита от SQL-инъекций (SQLi) — A03:2021

**Файлы:** `app/models.py`, `app/blueprints/api.py`, `app/blueprints/auth.py`,
`app/security/sanitize.py`

* **Весь доступ к БД идёт через ORM SQLAlchemy 2.x.** Значения передаются
  драйверу как bind-параметры и физически не могут стать частью текста запроса:

  ```python
  stmt = select(User).where(User.username == payload.username)
  user = db.s.execute(stmt).scalar_one_or_none()
  ```

* **Демонстрация prepared statement.** В `GET /api/data/{id}` намеренно
  используется «сырой» SQL — чтобы показать именованные параметры вместо
  конкатенации:

  ```python
  stmt = text(
      "SELECT id, owner_id, title, content, created_at, updated_at "
      "FROM notes WHERE id = :note_id"
  )
  row = db.s.execute(stmt, {"note_id": note_id}).mappings().first()
  ```

* **Никакой склейки строк.** Проверяется командой:

  ```bash
  grep -rniE "(execute|text)\(.*(f\"|%s|\+ )" app/    # пусто
  ```

  Дополнительно это контролирует правило **B608** (`hardcoded_sql_expressions`)
  в bandit и правило `S608` в ruff — оба включены в CI.

* **Экранирование wildcard'ов в поиске.** `?q=` уходит в БД параметром, но
  символы `%`, `_` и `\` дополнительно экранируются, чтобы поиск `100%` не
  превратился в «выбрать всё» (`escape_like()` в `app/security/sanitize.py`).

* **Типизированные path-параметры.** Маршруты объявлены как
  `/api/data/<int:note_id>` — строка `1 OR 1=1` не доходит до обработчика.

* **Allow-list на входе.** Логин соответствует `^[A-Za-z0-9_.-]{3,32}$`,
  неизвестные поля тела запроса отклоняются (`extra="forbid"`).

Тесты: `tests/test_security_sqli.py` — 7 классических payload'ов
(`' OR '1'='1`, `'; DROP TABLE users;--`, `UNION SELECT ... FROM users` и др.)
на трёх точках входа; проверяется, что таблицы на месте, чужие строки не
утекли, а payload сохранён как обычный текст.

### 2. Защита от XSS — A03:2021

**Файлы:** `app/security/sanitize.py`, `app/security/headers.py`,
`app/blueprints/api.py`

Для JSON-API главная защита — это правильный `Content-Type` плюс экранирование
на выходе, а не «фильтрация тегов» на входе (фильтры обходятся, а данные всё
равно потребляет фронтенд):

* **Экранирование на выходе.** Каждое поле, контролируемое пользователем,
  проходит через `sanitize_text()` → `markupsafe.escape()` (входит в состав
  Flask, дополнительная зависимость не нужна). `<script>` превращается в
  `&lt;script&gt;`, кавычки — в `&#34;` / `&#39;`. Даже если фронтенд вставит
  значение через `innerHTML`, исполнения не будет.
* **Нормализация на входе.** NFKC-нормализация, вырезание управляющих символов
  `\x00-\x08\x0b\x0c\x0e-\x1f\x7f-\x9f` (log forging, обход наивных фильтров),
  обрезка пробелов и ограничение длины.
* **Ответ всегда JSON.** Используется `jsonify`, ответы не рендерятся как HTML.
* **Заголовки безопасности на каждом ответе:**

  ```
  X-Content-Type-Options: nosniff
  X-Frame-Options: DENY
  Content-Security-Policy: default-src 'none'; frame-ancestors 'none'; base-uri 'none'; sandbox
  Referrer-Policy: no-referrer
  Permissions-Policy: geolocation=(), microphone=(), camera=(), interest-cohort=()
  Cross-Origin-Resource-Policy: same-origin
  Cross-Origin-Opener-Policy: same-origin
  Cache-Control: no-store
  Server: secure-rest-api
  ```

  `Strict-Transport-Security` добавляется при `ENABLE_HSTS=true`.
  Заголовок `Server` перезаписан, чтобы не раскрывать версию Werkzeug.
* **Экранируются даже сообщения об ошибках валидации** — имя поля приходит от
  атакующего и тоже проходит через `sanitize_text()` (`app/errors.py`).

Тесты: `tests/test_security_xss.py` — 6 payload'ов (`<script>alert(1)</script>`,
`<img src=x onerror=alert(1)>`, `"><svg/onload=alert(1)>`, `<iframe ...>` и др.);
проверяется, что в теле ответа нет ни одного «сырого» `<`, `>`, `"`, `'`,
content-type равен `application/json`, а `nosniff` на месте.

### 3. Защита от Broken Authentication — A07:2021

**Файлы:** `app/security/passwords.py`, `app/security/tokens.py`,
`app/security/decorators.py`, `app/blueprints/auth.py`

#### Пароли

* **bcrypt** с уникальной солью, cost-фактор 12 (`BCRYPT_ROUNDS`, в тестах 4).
  В БД хранится **только хэш** (`$2b$...`), открытый пароль не пишется ни в
  ответы, ни в логи.
* **Политика:** длина 12–72 байта, минимум 3 класса символов из 4, отказ по
  списку известных слабых паролей. Пароли длиннее 72 байт **отклоняются**, а не
  молча обрезаются (bcrypt игнорирует хвост, что ослабило бы пароль).
* **Защита от перебора учёток по времени ответа:** если пользователя нет,
  всё равно выполняется `bcrypt.checkpw` против фиктивного хэша — время ответа
  одинаковое.
* **Единое сообщение об ошибке** `"Invalid credentials."` для неверного пароля,
  несуществующего пользователя и отключённой учётной записи.

#### JWT

* **Алгоритм жёстко фиксирован HS256** при подписи *и* при проверке
  (`algorithms=["HS256"]`) — это блокирует атаку `alg: none` и алгоритмическую
  подмену.
* **Клеймы:** `sub`, `iat`, `nbf`, `exp`, `jti`, `sid`, `iss`, `aud`, `typ`.
  Все они объявлены обязательными (`options={"require": [...]}`) и
  **проверяются**, а не просто читаются; `iss` и `aud` сверяются с конфигурацией.
* **Разделение типов токенов:** `typ` = `access` | `refresh`. Refresh-токен не
  проходит на `/api/*`, access-токен не проходит на `/auth/refresh`.
* **TTL:** access — 15 минут, refresh — 7 дней.
* **Сессия (`sid`) и полноценный logout:** access- и refresh-токен, выданные
  одним логином, несут общий идентификатор сессии `sid`. `POST /auth/logout`
  заносит в `revoked_tokens` и `jti` конкретного токена, и `sid` всей сессии,
  а denylist проверяется по обоим значениям на каждом запросе. Без `sid` logout
  был бы **неполным**: отзыв только access-токена оставлял бы refresh-токен
  живым, и клиент тут же выпустил бы себе новый access-токен. При этом logout на
  одном устройстве не разлогинивает остальные сессии — у них свой `sid`.
  Токен, полученный через `/auth/refresh`, наследует `sid` и умирает вместе с
  сессией. Команда `flask purge-tokens` чистит устаревшие записи.
* **Никаких секретов в коде.** `JWT_SECRET_KEY` берётся только из окружения.
  В production приложение **не стартует**, если ключ пустой, короче 32 символов,
  является известной заглушкой или собран менее чем из 8 разных символов. Вне
  production генерируется случайный ключ на процесс — то есть пригодного
  дефолтного ключа не существует нигде в репозитории.

#### Middleware

`app/security/decorators.py` — декоратор `@jwt_required(token_type="access")`,
которым явно помечен каждый защищённый эндпоинт (явный декоратор надёжнее
глобального `before_request`: новый blueprint нельзя случайно оставить
открытым). Он:

1. строго парсит `Authorization: Bearer <token>` (ровно две части, схема
   регистронезависимо `bearer`, непустой токен);
2. проверяет подпись, срок, `iss`, `aud`, обязательные клеймы и `typ`;
3. проверяет denylist — и по `jti` токена, и по `sid` его сессии;
4. загружает пользователя и проверяет `is_active` — токен удалённой или
   заблокированной учётки не работает;
5. кладёт объект в `flask.g.current_user`.

Любая ошибка → `401` + `WWW-Authenticate: Bearer`, событие пишется в лог.

#### Rate limiting

Flask-Limiter: `/auth/login` — 5/минуту и 20/час на IP, `/auth/register` —
5/час, глобальный дефолт — 200/час. Ответ при превышении — `429` в том же
JSON-формате.

### 4. Дополнительные меры

| Мера | Где |
| --- | --- |
| **Broken Access Control (A01):** проверка владельца в `GET`/`DELETE /api/data/{id}` → 403; список и поиск всегда фильтруются по `owner_id` | `app/blueprints/api.py` |
| Строгая валидация входа pydantic v2, `extra="forbid"` (защита от mass assignment) | `app/schemas.py` |
| Ограничение размера тела запроса 64 КБ → 413 | `app/config.py` |
| `DEBUG=False` в production, трейсбеки наружу не отдаются | `app/config.py`, `app/errors.py` |
| CORS выключен, пока origin'ы не внесены в allow-list явно | `app/__init__.py` |
| Структурные JSON-логи событий `auth.login.success/failure`, `auth.token.rejected`, `authz.denied`, `token.revoked` — без паролей и токенов | `app/logging_conf.py` |
| Docker: multi-stage, непривилегированный пользователь, `cap_drop: ALL`, `no-new-privileges`, read-only ФС, gunicorn | `Dockerfile`, `docker-compose.yml` |

Полная модель угроз с маппингом на OWASP Top 10 2021 —
**[`docs/THREAT-MODEL.md`](docs/THREAT-MODEL.md)** (20 угроз, контроли и
остаточные риски).

---

## CI/CD pipeline с security-сканерами

Файл: **[`.github/workflows/ci.yml`](.github/workflows/ci.yml)**

**Триггеры:** `push` (main / master / develop / feature/**), `pull_request`,
`workflow_dispatch`, а также еженедельный `schedule` — чтобы новые CVE
находились даже без коммитов.

| Job | Инструмент | Что делает | Блокирует pipeline |
| --- | --- | --- | --- |
| `lint` | ruff | стиль + правила `flake8-bandit` (`S`) | да |
| `test` | pytest, матрица Python 3.11 / 3.12 | тесты, порог покрытия 85% | да |
| **`sast`** | **bandit** | отчёты txt / JSON / SARIF, выгрузка в GitHub Code Scanning; падает на находках **medium+** | **да** |
| **`sca`** | **pip-audit** | аудит `requirements.txt` и `requirements-dev.txt`; падает на любой известной CVE | **да** |
| `sca-owasp` | OWASP Dependency-Check | HTML-отчёт артефактом (нужен `NVD_API_KEY`) | нет |
| `secrets-scan` | gitleaks | поиск секретов в истории | нет |
| `security-gate` | — | сводная таблица результатов; именно этот job ставится в branch protection | да |

Настройки безопасности самого pipeline: `permissions: contents: read` на верхнем
уровне (`security-events: write` только в SAST-джобе), `concurrency` с отменой
предыдущего прогона, все версии зависимостей запинены точно (`==`).

Каждый job пишет читаемую сводку в `$GITHUB_STEP_SUMMARY` — именно оттуда
удобно делать скриншоты для отчёта.

Дополнительно: **[`.github/dependabot.yml`](.github/dependabot.yml)** —
еженедельные обновления `pip`, `github-actions` и `docker`.

### Локальный запуск тех же проверок

```bash
make lint       # ruff check + ruff format --check
make coverage   # pytest с порогом покрытия 85%
make sast       # bandit -c bandit.yaml -r app -ll
make sca        # pip-audit -r requirements.txt
make security   # sast + sca
```

### Про `NVD_API_KEY`

Job `sca-owasp` скачивает базу NVD, которая без API-ключа жёстко ограничена по
скорости. Ключ бесплатный:
<https://nvd.nist.gov/developers/request-an-api-key> → добавить в
`Settings → Secrets and variables → Actions → New repository secret` с именем
`NVD_API_KEY`. Без ключа job не падает — он помечен `continue-on-error`, потому
что обязательный SCA обеспечивает `pip-audit`.

### Замечание про Python 3.9

Python 3.9 снят с поддержки, и часть исправлений безопасности в зависимостях
выпущена **только** для Python 3.10+. Поэтому в `requirements*.txt`
используются environment markers: на всех рабочих окружениях (матрица CI
3.11/3.12, Docker-образ, production) ставятся **исправленные** версии, и
`pip-audit` там проходит без единого исключения. Список исключений для
локального интерпретатора 3.9 вынесен в `Makefile` (`PY39_EXCEPTIONS`) с
разбором достижимости каждой CVE — см. **[`SECURITY.md`](SECURITY.md)**.

### Почему зелёный pipeline может покраснеть сам собой

Это нормальное поведение SCA, а не поломка. `pip-audit` сверяет версии
зависимостей с базой advisory, которая пополняется ежедневно: код не менялся, а
для уже запиненной версии опубликовали CVE — и гейт справедливо падает. Именно
для этого в workflow стоит еженедельный триггер `schedule`, а в
`.github/dependabot.yml` — автоматические PR с обновлениями.

Что делать, когда упал job **SCA (pip-audit)**:

```bash
make audit                     # воспроизвести локально и увидеть ID и Fix Versions
```

1. Посмотреть в отчёте колонку `Fix Versions`.
2. Если исправленный релиз поддерживает Python, на котором мы запускаемся, —
   **поднять пин** в `requirements*.txt`. Это и есть починка.
3. Прогнать тесты: `make coverage` — обновление зависимости может поменять
   поведение (например, фиксы в PyJWT ужесточают валидацию ключей).
4. Добавлять advisory в `PY39_EXCEPTIONS` — только если исправленной версии для
   нашего Python вообще не существует, и с записью разбора достижимости в
   `SECURITY.md`.

**Реальный пример из истории проекта.** Через три недели после первого коммита
pipeline покраснел без изменений кода: на `PyJWT 2.13.0` опубликовали 12
advisory (в том числе обход защиты от HS/asymmetric confusion и `RecursionError`
в `jwt.decode()`), на `urllib3 2.7.0` — ещё 3. Починка — подъём до
`PyJWT==2.15.1` и `urllib3==2.8.0`, оба набора advisory закрываются полностью.

---

## Скриншоты отчётов SAST/SCA

Положите скриншоты в `docs/screenshots/` и раскомментируйте ссылки ниже.

Что снимать (вкладка **Actions** репозитория → последний успешный запуск):

1. **Общий вид запуска** — список всех job'ов с зелёными галочками.
2. **SAST (bandit)** — job `SAST (bandit)`, блок `### SAST - bandit` в Summary
   с `No issues identified.` и метриками `Medium: 0 / High: 0`.
3. **SCA (pip-audit)** — job `SCA (pip-audit)`, блок `### SCA - pip-audit` с
   `No known vulnerabilities found`.
4. **Security gate** — сводная таблица с результатами всех обязательных job'ов.
5. (опционально) вкладка **Security → Code scanning alerts** — результаты
   bandit, загруженные в формате SARIF.

```markdown
<!-- ![Общий вид пайплайна](docs/screenshots/01-pipeline-overview.png) -->
<!-- ![SAST — bandit](docs/screenshots/02-sast-bandit.png) -->
<!-- ![SCA — pip-audit](docs/screenshots/03-sca-pip-audit.png) -->
<!-- ![Security gate](docs/screenshots/04-security-gate.png) -->
```

**Ссылка на последний успешный запуск pipeline:**
`https://github.com/OWNER/REPO/actions/workflows/ci.yml` ← заменить на
конкретный run после первого push.

---

## Тестирование

```bash
make test                # быстрый прогон
make coverage            # с порогом покрытия 85%
```

194 теста, покрытие 98%:

| Файл | Что проверяет |
| --- | --- |
| `tests/test_health.py` | liveness, все заголовки безопасности, JSON-ошибки на 404/405 |
| `tests/test_auth.py` | регистрация, дубликат → 409, слабый пароль → 422, пароль >72 байт → 422, хранение только хэша, логин, одинаковый ответ для неверного пароля и несуществующего пользователя, refresh, logout + повторное использование токена, завершение сессии (после logout не работает и refresh-токен, и выпущенный через него access-токен), независимость параллельных сессий, обязательность клейма `sid` |
| `tests/test_api_data.py` | 401 без токена, 200 с токеном, создание 201, пагинация, поиск, 404/204, тело >64 КБ → 413 |
| `tests/test_security_sqli.py` | 7 SQLi-payload'ов на трёх точках входа, сохранность схемы и данных, экранирование LIKE-wildcard'ов |
| `tests/test_security_xss.py` | 6 XSS-payload'ов, экранирование в ответах и в ошибках валидации, content-type |
| `tests/test_security_authn.py` | испорченная подпись, `alg: none`, чужой секрет, истёкший и ещё не действующий токен, чужие `iss`/`aud`, отсутствующие клеймы, refresh на `/api/*`, 9 вариантов кривого заголовка `Authorization`, токен удалённой/заблокированной учётки, свойства bcrypt |
| `tests/test_security_authz.py` | IDOR: пользователь A не читает и не удаляет заметки пользователя B |
| `tests/test_config_and_cli.py` | валидация production-конфига, CORS allow-list, opaque 500, rate limiting, CLI-команды |
| `tests/test_units.py` | хелперы окружения, нормализация, denylist, JSON-логгер |

---

## Структура проекта

```
lab1-secure-rest-api/
├── .github/
│   ├── workflows/ci.yml          # pipeline: lint, test, SAST, SCA, gate
│   ├── dependabot.yml
│   └── pull_request_template.md  # чек-лист безопасности для ревью
├── app/
│   ├── __init__.py               # фабрика create_app()
│   ├── config.py                 # конфиг из env, fail-closed в production
│   ├── extensions.py             # SQLAlchemy engine/session, Flask-Limiter
│   ├── models.py                 # User, Note, RevokedToken
│   ├── schemas.py                # pydantic-валидация входа
│   ├── errors.py                 # единый JSON-формат ошибок
│   ├── logging_conf.py           # JSON-логи без секретов
│   ├── cli.py                    # init-db / seed-db / create-user / purge-tokens
│   ├── security/
│   │   ├── passwords.py          # bcrypt, политика, анти-энумерация
│   │   ├── tokens.py             # выпуск/проверка/отзыв JWT
│   │   ├── decorators.py         # @jwt_required — middleware
│   │   ├── sanitize.py           # экранирование (XSS), escape_like
│   │   └── headers.py            # заголовки безопасности
│   └── blueprints/
│       ├── auth.py               # /auth/*
│       ├── api.py                # /api/*
│       └── health.py             # /health
├── tests/                        # 189 тестов
├── docs/
│   ├── API.md                    # полная спецификация API
│   ├── THREAT-MODEL.md           # модель угроз, OWASP Top 10 2021
│   ├── curl-examples.sh          # сквозной сценарий проверки
│   ├── postman_collection.json   # коллекция Postman v2.1
│   └── screenshots/              # сюда класть скриншоты отчётов
├── wsgi.py                       # точка входа (gunicorn wsgi:app)
├── requirements.txt              # runtime, версии запинены ==
├── requirements-dev.txt          # тесты, линтер, SAST, SCA
├── pyproject.toml                # ruff / pytest / coverage
├── bandit.yaml                   # конфигурация SAST
├── Dockerfile / docker-compose.yml
├── Makefile                      # make help
├── .env.example                  # все переменные окружения
├── SECURITY.md                   # политика раскрытия + принятые риски
└── README.md
```

---

## Переменные окружения

Полный список с комментариями — в [`.env.example`](.env.example).
Файл `.env` в `.gitignore` и **не должен попадать в репозиторий**.
Приложение не читает `.env` автоматически (зависимость `python-dotenv`
намеренно убрана), загрузите его явно:

```bash
set -a && . ./.env && set +a
```

| Переменная | По умолчанию | Назначение |
| --- | --- | --- |
| `APP_ENV` | `development` | `development` / `testing` / `production` |
| `JWT_SECRET_KEY` | — | **обязательна в production** (≥32 символов). Генерация: `python -c "import secrets; print(secrets.token_urlsafe(48))"` |
| `JWT_ISSUER` / `JWT_AUDIENCE` | `lab1-secure-rest-api` / `...-clients` | проверяемые клеймы `iss` / `aud` |
| `ACCESS_TOKEN_TTL_MINUTES` | `15` | срок жизни access-токена |
| `REFRESH_TOKEN_TTL_DAYS` | `7` | срок жизни refresh-токена |
| `BCRYPT_ROUNDS` | `12` | cost-фактор bcrypt |
| `DATABASE_URL` | `sqlite:///app.db` | строка подключения (поддерживается PostgreSQL) |
| `RATELIMIT_ENABLED` | `true` | включение rate limiting |
| `RATELIMIT_LOGIN` / `RATELIMIT_REGISTER` | `5 per minute;20 per hour` / `5 per hour` | лимиты на аутентификацию |
| `CORS_ORIGINS` | пусто | allow-list origin'ов через запятую |
| `ENABLE_HSTS` | `false` (в production `true`) | заголовок HSTS |
| `MAX_CONTENT_LENGTH` | `65536` | максимальный размер тела запроса |
| `LOG_LEVEL` / `JSON_LOGGING` | `INFO` / `true` | логирование |

---

## Запуск в Docker

```bash
make docker-build

JWT_SECRET_KEY="$(python3 -c 'import secrets; print(secrets.token_urlsafe(48))')" \
  docker compose up
```

Образ: multi-stage на `python:3.12-slim`, gunicorn, пользователь `appuser`
(uid 10001), read-only файловая система, `cap_drop: ALL`,
`no-new-privileges:true`, healthcheck на `/health`. Без `JWT_SECRET_KEY`
контейнер намеренно не стартует.

---

## Известные ограничения и дальнейший план

Раздел честно фиксирует, где проходит граница текущей реализации, и что делать
дальше. Учебная задача закрыта полностью; всё перечисленное ниже — это то, что
отделяет лабораторную работу от боевого сервиса.

### Осознанные компромиссы текущей версии

| Что | Почему так сделано | Чем плохо |
| --- | --- | --- |
| **Экранирование на выходе делает API «лишённым» исходного значения** | Задание прямо требует «санитизировать все пользовательские данные, которые возвращаются в ответах API», поэтому `title`/`content` возвращаются уже HTML-экранированными | Клиент получает `O&#39;Brien`, а не `O'Brien`. Каноничнее — хранить и отдавать сырое значение, а экранировать в момент вставки в DOM на стороне потребителя |
| **Чужой ресурс отдаёт `403`, а не `404`** | Так проверка владения видна в ответе и её легко продемонстрировать при защите работы | `403` подтверждает, что объект с таким id существует, то есть позволяет перебором составить карту чужих ресурсов. Для боевого API правильнее `404` |
| **Rate limiting хранится в памяти процесса (`memory://`)** | Нет внешних зависимостей, работает «из коробки» | При нескольких воркерах gunicorn у каждого свой счётчик, лимит фактически умножается на число воркеров |
| **Ключ клиента лимитера — `remote_addr`** | Нет обратного прокси в учебной схеме | За прокси/балансировщиком все запросы придут с одного IP. Нужен `ProxyFix` + доверенный `X-Forwarded-For` |
| **SQLite и `db.create_all()`** | Достаточно для лабораторной, ничего не нужно поднимать | Нет миграций, нет конкурентной записи. `DATABASE_URL` уже умеет PostgreSQL — не хватает Alembic |
| **`click` 8.1.8 на Python 3.9** | Патч 8.3.3 требует Python ≥ 3.10, а локальный интерпретатор — 3.9 | Формально числится CVE. Путь `click.edit()` в коде не вызывается, а CI, Docker и production ставят 8.3.3 по environment-маркеру |

### Дальнейший план

**Приоритет 1 — безопасность аутентификации**

1. **Ротация refresh-токенов с детекцией повторного использования.** Сейчас
   `/auth/refresh` выдаёт новый access-токен, но сам refresh-токен не меняется и
   живёт все 7 дней. Нужно: на каждый refresh выпускать новую пару, старый `jti`
   гасить, а повторное предъявление уже погашенного refresh-токена трактовать как
   компрометацию и убивать всю сессию по `sid`.
2. **Блокировка учётной записи после серии неудачных входов** (экспоненциальная
   задержка либо временный lock) — rate limiting по IP обходится ботнетом.
3. **Проверка пароля по базе утечек** — Have I Been Pwned Range API
   (k-анонимность, отправляются первые 5 символов SHA-1). Сейчас список слабых
   паролей — символическая выборка из 9 значений.
4. **Второй фактор (TOTP)** для `/auth/login` и step-up при чувствительных
   операциях.

**Приоритет 2 — эксплуатационная зрелость**

5. **Alembic-миграции** вместо `create_all()`, чтобы схема менялась
   контролируемо.
6. **Redis как хранилище лимитера и denylist'а** — общий счётчик для всех
   воркеров и переживающий рестарт список отозванных сессий.
7. **`ProxyFix` + доверенный список прокси**, иначе за балансировщиком ломаются
   и rate limiting, и IP в логах аудита.
8. **Периодическая очистка denylist'а** — команда `flask purge-tokens` уже есть,
   её нужно повесить на cron/K8s CronJob.
9. **TLS и `ENABLE_HSTS=true`.** JWT — bearer-credential: без HTTPS весь блок
   аутентификации обходится перехватом трафика.

**Приоритет 3 — усиление pipeline**

10. **Добавить Semgrep** (правила `p/owasp-top-ten`) рядом с bandit: bandit ищет
    опасные вызовы, Semgrep — небезопасные паттерны потока данных.
11. **DAST-этап.** Работа 4 курса посвящена OWASP ZAP — логично поднимать
    контейнер с API в pipeline и прогонять ZAP Baseline Scan против живого
    сервиса, а не только статику.
12. **Подпись артефактов и SBOM** — `pip-audit --format cyclonedx` даёт SBOM,
    его стоит публиковать как артефакт релиза.
13. **Branch protection**: сделать `Security gate` обязательной проверкой и
    запретить push в `main` напрямую.
14. **Сделать OWASP Dependency-Check блокирующим** после добавления
    `NVD_API_KEY` — сейчас job намеренно `continue-on-error`, потому что без
    ключа фид NVD упирается в rate limit.

**Приоритет 4 — функциональность API**

15. Обновление заметки (`PATCH /api/data/{id}`) и мягкое удаление.
16. Роли и права (`user` / `admin`) — сейчас модель доступа плоская: каждый видит
    только свои объекты, административного среза нет.
17. OpenAPI-спецификация, генерируемая из pydantic-схем, и Swagger UI вместо
    рукописного `docs/API.md`.

---

## Лицензия

[MIT](LICENSE)
