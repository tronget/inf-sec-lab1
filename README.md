# Информационная безопасность

## Лабораторная работа №1: Разработка защищённого REST API с интеграцией в CI/CD

[![CI](https://github.com/tronget/inf-sec-lab1/actions/workflows/ci.yml/badge.svg)](https://github.com/tronget/inf-sec-lab1/actions/workflows/ci.yml)

Учебный сервис заметок: пользователь регистрируется, входит по логину и паролю, получает JWT и работает только со своими заметками. Пароли хранятся в виде bcrypt-хэшей, доступ к данным идёт через ORM, пользовательские данные экранируются на выходе. На каждый push и pull request GitHub Actions прогоняет SAST- и SCA-сканеры.

### Стек

- Python / Flask
- SQLAlchemy 2.x + SQLite
- PyJWT (HS256), bcrypt, pydantic v2
- GitHub Actions: bandit (SAST), pip-audit (SCA), OWASP Dependency-Check

### Запуск

```bash
git clone https://github.com/tronget/inf-sec-lab1.git
cd inf-sec-lab1
python3 -m venv .venv
.venv/bin/pip install -r requirements.txt
make run                      # http://127.0.0.1:8000
```

Сквозная проверка API одной командой — `./docs/curl-examples.sh`: регистрация → login → запрос без токена (401) → с токеном (200) → создание заметки → logout → 401 с отозванным токеном. Для Postman — `docs/postman_collection.json`.

### Описание API

| Метод | Путь | Доступ | Назначение |
|---|---|---|---|
| `POST` | `/auth/register` | открытый | Регистрация: логин и пароль |
| `POST` | `/auth/login` | открытый | **П.1 задания.** Принимает логин и пароль, возвращает JWT |
| `POST` | `/auth/refresh` | refresh JWT | Обновление access-токена |
| `POST` | `/auth/logout` | access JWT | Завершение сессии: отзыв access- и refresh-токена |
| `GET` | `/api/data` | access JWT | **П.2 задания.** Заметки текущего пользователя |
| `POST` | `/api/data` | access JWT | **П.3 задания (свой метод).** Создание заметки |
| `GET` | `/api/data/{id}` | access JWT | Одна заметка, с проверкой владельца |
| `DELETE` | `/api/data/{id}` | access JWT | Удаление своей заметки |
| `GET` | `/api/me` | access JWT | Профиль текущего пользователя |
| `GET` | `/health` | открытый | Проба живости |

Вход возвращает пару токенов:

```bash
curl -s -X POST http://127.0.0.1:8000/auth/login \
  -H 'Content-Type: application/json' \
  -d '{"username":"alice","password":"Alice-Str0ng!Pass"}'
# → 200 { "token_type": "Bearer", "access_token": "eyJhbGciOiJIUzI1NiJ9...",
#         "refresh_token": "eyJhbGciOiJIUzI1NiJ9...", "expires_in": 900 }
```

Access-токен передаётся в защищённые запросы заголовком `Authorization: Bearer <access_token>`:

```bash
curl -s http://127.0.0.1:8000/api/data -H "Authorization: Bearer $ACCESS"
# → 200 { "items": [...], "page": 1, "per_page": 20, "total": 0 }

curl -s -X POST http://127.0.0.1:8000/api/data \
  -H "Authorization: Bearer $ACCESS" -H 'Content-Type: application/json' \
  -d '{"title":"Заголовок","content":"Текст заметки"}'
# → 201 { "id": 1, "owner_id": 1, "title": "Заголовок", ... }
```

Без действительного JWT защищённые методы возвращают `401` с заголовком `WWW-Authenticate: Bearer`. Чужая заметка — `403`. Полная спецификация с телами запросов, ответов и всеми кодами ошибок — в [`docs/API.md`](docs/API.md).

### Описание реализованных мер защиты

- От **SQLi** код защищён ORM SQLAlchemy 2.x: пользовательские значения уезжают драйверу как bind-параметры и не могут стать частью текста запроса. Конкатенация строк для сборки SQL не используется нигде.

  ```python
  stmt = select(User).where(User.username == payload.username)
  user = db.s.execute(stmt).scalar_one_or_none()
  ```

  Там, где запрос написан вручную через `text()`, значения тоже передаются именованными параметрами (`:note_id`) — это prepared statement.

- От **XSS** защищает экранирование пользовательских данных на выходе через `markupsafe.escape` — `<script>` возвращается как `&lt;script&gt;` и не исполняется, даже если фронтенд вставит значение через `innerHTML`.

  ```python
  def sanitize_text(value):
      return str(escape(strip_control_chars(str(value))))
  ```

  Дополнительно каждый ответ уходит с `Content-Type: application/json` и заголовками `X-Content-Type-Options: nosniff`, `Content-Security-Policy: default-src 'none'; sandbox`, `X-Frame-Options: DENY`.

- Пароли хранятся только как **bcrypt**-хэши с уникальной солью, cost-фактор 12. Пароль нигде не логируется и не возвращается.

  ```python
  bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt(rounds=rounds))
  ```

- Если пользователя нет, bcrypt всё равно вызывается против фиктивного хэша — время ответа одинаковое, перебрать существующие логины по таймингу нельзя. Сообщение об ошибке одно на все случаи: `Invalid credentials`.
- После успешного входа выдаётся **JWT**, подписанный **HS256**, со сроком жизни 15 минут. Секрет подписи берётся из переменной окружения `JWT_SECRET_KEY` и в репозитории не хранится; в production приложение не стартует со слабым или отсутствующим ключом.
- Алгоритм жёстко зафиксирован при проверке (`algorithms=["HS256"]`) — это блокирует атаку `alg: none` и подмену алгоритма. Клеймы `exp`, `iat`, `nbf`, `sub`, `jti`, `sid`, `iss`, `aud`, `typ` объявлены обязательными и проверяются, а не просто читаются.

- Middleware — декоратор `@jwt_required()`, которым явно помечен каждый защищённый эндпоинт: он разбирает заголовок `Authorization`, проверяет подпись, срок, издателя, аудиторию и тип токена, сверяется со списком отозванных и загружает пользователя.
- `POST /auth/logout` заносит в denylist и `jti` токена, и `sid` всей сессии, поэтому выданный тем же входом refresh-токен тоже перестаёт работать.
- Владелец заметки берётся из проверенного токена, а не из тела запроса; список и поиск всегда фильтруются по `owner_id`, обращение к чужой записи даёт `403`.
- Брутфорс логина ограничен rate limiting (5 запросов в минуту на IP), тело запроса — 64 КБ, вход валидируется pydantic с `extra="forbid"`.


### Отчеты из pipeline

Пайплайн запускается на каждый push и pull request. Блокирующие проверки: `lint` (ruff), `test` (pytest на Python 3.11 и 3.12), **`sast` (bandit)** и **`sca` (pip-audit)**; их результат сводит job `security-gate`.

bandit (SAST):

<!-- ![SAST — bandit](docs/screenshots/02-sast-bandit.png) -->

pip-audit (SCA):

<!-- ![SCA — pip-audit](docs/screenshots/03-sca-pip-audit.png) -->

Security gate:

<!-- ![Security gate](docs/screenshots/04-security-gate.png) -->

Последний успешный запуск пайплайна:
https://github.com/tronget/inf-sec-lab1/actions/runs/<RUN_ID>

### Дополнительная документация

[`docs/API.md`](docs/API.md) — полная спецификация API · [`docs/THREAT-MODEL.md`](docs/THREAT-MODEL.md) — модель угроз с привязкой к OWASP Top 10 · [`SECURITY.md`](SECURITY.md) — политика раскрытия уязвимостей

### Лицензия

[MIT](LICENSE)
