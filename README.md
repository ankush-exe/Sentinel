# Sentinel

Sentinel is a small security-testing demo that discovers authenticated path-parameter endpoints from OpenAPI, replays each resource request as three roles, and reports broken object-level authorization (BOLA/IDOR).

The reusable package is exposed as `sentinel_appsec`, with a `sentinel scan <url>` command.

## 30-second demo

```bash
cd Sentinel
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
uvicorn demo_app.main:app --port 8001
```

In another terminal:

```bash
source .venv/bin/activate
uvicorn backend.main:app --port 8000
```

Open http://localhost:8000, leave the target as `http://localhost:8001`, and click **Run Security Test**. The report should show two high-severity BOLA/IDOR findings and two secured endpoints that remain clean. Each finding also includes a generated pytest regression test.

## Demo tokens

- `token-user-a` represents `user_a`, who owns report `1`.
- `token-user-b` represents `user_b`.
- `token-admin` represents `admin`.

The vulnerable demo routes intentionally omit ownership checks. The `/owner` route checks ownership and the `/admin-summary` route checks role. This makes the result useful for a live demonstration rather than a scanner that flags every route.

## Tests

```bash
pytest -q
```

## Package usage

```bash
python -m pip install -e .
sentinel scan http://localhost:8001
```

The default CLI output is a human-readable risk summary with evidence and remediation suggestions. Use `sentinel scan --json http://localhost:8001` when another tool needs the complete structured report.

The scanner is deliberately limited to OpenAPI parsing. It does not crawl, use a production database, or implement production authentication/deployment.
