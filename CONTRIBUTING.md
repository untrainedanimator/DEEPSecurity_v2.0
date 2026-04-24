# Contributing

## Setup

```bash
git clone https://github.com/your-account/deepsecurity.git
cd deepsecurity
python -m venv .venv
source .venv/bin/activate     # Windows: .venv\Scripts\activate
make dev-install
```

## Before you open a PR

```bash
make format       # ruff auto-format + fix
make lint         # ruff check (should be clean)
make typecheck    # mypy (advisory for now)
make test         # pytest
```

CI will run the same commands plus `pip-audit` and a Docker build.

## Commit messages

Conventional Commits, loosely:

```
feat: short imperative summary
fix: ...
refactor: ...
test: ...
docs: ...
chore: ...
```

One logical change per commit. Keep history tellable.

## Adding a new detection layer

If you want to bolt on a new detection signal (YARA, VT lookup, sigstore, ...):

1. Add a new module under `deepsecurity/` exposing a pure function
   `feats, context -> Verdict`. No I/O side effects from the function itself.
2. Wire it into `deepsecurity/scanner.py::classify()` with explicit precedence
   in the decision table.
3. Add test cases to `tests/test_scanner.py` covering the new signal alone
   and in combination with existing layers.
4. Update `docs/ARCHITECTURE.md` and the README's detection-policy table.

## Adding a new API route

1. The route lives in the appropriate blueprint under `deepsecurity/api/`.
2. It must use `@require_role(...)` unless it is intentionally public
   (`/healthz`, `/readyz`, `/api/auth/login`).
3. Any filesystem path from the client goes through `resolve_under_root()`.
4. Any file-mutating action writes to the audit log via `audit_log()`.
5. Add an integration test in `tests/test_api_*.py`.
