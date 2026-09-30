# Security Policy

This is an educational project, but it is developed and reviewed as if it were
production software.

## Reporting a vulnerability

Please open a **private** security advisory through
`Security -> Advisories -> Report a vulnerability` on the GitHub repository,
or contact the maintainer directly. Do not open a public issue for an
unpatched vulnerability.

Please include: affected endpoint, a reproduction (request/response), the
impact you believe it has, and the commit you tested.

Expected response time: 72 hours for an acknowledgement.

## Supported versions

Only the `main` branch is supported.

## Automated controls

Every push and pull request runs:

| Control | Tool | Gate |
| --- | --- | --- |
| SAST | `bandit` | fails on MEDIUM or HIGH severity |
| SCA | `pip-audit` | fails on any known CVE in a pinned dependency |
| SCA (informational) | OWASP Dependency-Check | report only |
| Secret scanning | `gitleaks` | report only |
| Tests | `pytest` | fails below 85% line coverage |
| Lint | `ruff` (including the `flake8-bandit` rule set) | fails on any finding |

Dependabot opens weekly update pull requests for `pip`, `github-actions` and
`docker`.

## Handling of secrets

* No secret is ever committed. `.env` is git-ignored; `.env.example` contains
  empty placeholders only.
* `JWT_SECRET_KEY` is read from the environment. In production the application
  **refuses to start** if it is missing, shorter than 32 characters, a
  well-known placeholder, or built from fewer than 8 distinct characters
  (`app/config.py::ProductionConfig.validate`).
* Outside production a random per-process key is generated, so there is no
  usable default key anywhere in the source tree.
* Passwords, password hashes and raw JWTs are never written to the logs. Log
  records carry only a user id, a token `jti` and the client IP.

## Known accepted risk: the legacy Python 3.9 development interpreter

Python 3.9 is end-of-life. Several dependencies have published security fixes
**only** for Python 3.10 and newer:

| Advisory | Package | Fixed in | Fix requires |
| --- | --- | --- | --- |
| PYSEC-2026-2132 (CVE-2026-7246) | click | 8.3.3 | Python >= 3.10 |
| PYSEC-2026-1845 | pytest | 9.0.3 | Python >= 3.10 |
| PYSEC-2026-2275 | requests | 2.33.0 | Python >= 3.10 |
| PYSEC-2026-141, PYSEC-2026-142 | urllib3 | 2.7.0 | Python >= 3.10 |
| GHSA-8988-9cw3-xx77 (CVE-2026-97687), GHSA-gh4c-6fx4-qh6g (CVE-2026-97688), GHSA-vxq7-64xx-v4gw (CVE-2026-97689) | urllib3 | 2.8.0 | Python >= 3.10 |
| PYSEC-2026-3625 | msgpack | 1.2.1 | Python >= 3.10 |
| PYSEC-2026-1374, PYSEC-2026-1375 | filelock | 3.20.3 | Python >= 3.10 |

`requirements.txt` and `requirements-dev.txt` therefore use environment
markers: **every runtime that actually ships or tests this code - the CI matrix
(3.11 / 3.12), the Docker image and production - installs the patched
release**, and the pipeline audits with no exceptions whatsoever.

The exception list applies only to a developer whose local interpreter is
Python 3.9, and it is encoded explicitly in the `Makefile` (`PY39_EXCEPTIONS`)
so that it is visible in code review rather than hidden in a scanner config.

Reachability of the only advisory that touches a *runtime* dependency:

* **CVE-2026-7246 (click)** is a command-injection issue in `click.edit()`.
  This project never calls `click.edit()` - `grep -rn "click.edit" app/`
  returns nothing. Click is used solely by Flask's own CLI, and the CLI is not
  exposed to untrusted input.

Every other advisory in the table above affects development-only tooling
(`pytest`, and the transitive dependencies of `pip-audit`), which never runs in
production. In particular `urllib3` reaches this project only as a transitive
dependency of `pip-audit` itself - the service never makes outbound HTTP calls
and imports no HTTP client
(`grep -rnE '^(import|from) (urllib|requests|httpx)' app/` returns nothing), so
the HTTP-client advisories above are unreachable from the service.

### Keeping this list honest

Advisories are published continuously, so a pipeline that was green yesterday
can legitimately go red today without a single line of code changing - the
weekly `schedule` trigger in `.github/workflows/ci.yml` exists precisely to
surface that. When the SCA gate fails:

1. read the finding, do **not** add it to `PY39_EXCEPTIONS` reflexively;
2. if a fixed release exists for the runtimes we ship on, **bump the pin** -
   that is the fix;
3. only when *every* fixed release requires a newer Python than the local
   development interpreter does the version get an environment marker, with the
   advisory id recorded in the table above.

**Recommendation:** develop on Python 3.11 or newer. Python 3.9 is supported
only so that the project runs on the currently installed interpreter.
