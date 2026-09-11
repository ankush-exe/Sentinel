# Sentinel

Sentinel is a small security-testing demo that discovers authenticated path-parameter endpoints from OpenAPI, replays each resource request as three roles, and reports broken object-level authorization (BOLA/IDOR).

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

The scanner is deliberately limited to OpenAPI parsing. It does not crawl, package for PyPI, provide a CLI, use a production database, or implement production authentication/deployment.
