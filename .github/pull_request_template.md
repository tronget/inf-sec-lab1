## What changed

<!-- A short description of the change. -->

## Security checklist

- [ ] No secret, token or password is committed (checked `git diff` and `.env` is ignored)
- [ ] All database access goes through SQLAlchemy bound parameters - no string-built SQL
- [ ] Every value echoed back to a client passes through `sanitize_text()`
- [ ] New endpoints are decorated with `@jwt_required()` unless they are deliberately public
- [ ] Ownership/authorisation is checked for every single-resource route
- [ ] Input is validated with a pydantic schema (`extra="forbid"`)
- [ ] Tests cover the happy path *and* the rejection path
- [ ] `make security` passes locally (bandit + pip-audit)

## Pipeline

- [ ] `lint`, `test`, `sast` and `sca` are green on this branch
