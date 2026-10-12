# Repository Guidelines

## Project Structure & Module Organization

This guide covers `Product/api`, the multi-tenant SOC alert classifier.

- `app/main.py` defines FastAPI routes; `validation.py` extracts alerts; `field_mapping.py` and `preprocessing.py` normalize features; `pipeline.py` performs inference.
- `model_store.py` reads artifacts per `(tenant, version)` from MinIO or a local mirror and verifies manifest SHA-256 checksums; `tenant_registry.py` caches loaded models (LRU); `manifest.py` and `config.py` handle schemas and configuration inside `app/`.
- `models/tenants/<TENANT>/versions/<VERSION>/` mirrors the MinIO key layout: four `.pkl` files plus `manifest.json`; use `models/tenants/VND/versions/v1.0/` as the example. Loose `.pkl` files directly in `models/` are unused legacy copies.
- `sample_batch.json` provides manual request fixtures; `tests/` contains API/logging, model-store, registry, and field-mapping tests.

## Build, Test, and Development Commands

Run commands from `Product/api` using Python 3.11. PowerShell setup:

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
$env:MODEL_STORE = "local"
$env:MODELS_ROOT = (Resolve-Path .\models).Path
python -m uvicorn app.main:app --reload --port 8000
```

These commands create an isolated environment, install pinned dependencies, and start development serving. Browse `http://localhost:8000/docs` for interactive requests.

- `docker build -t soc-alert-classifier:2.0 .` builds the deployment image.
- `docker run --rm -p 8000:8000 soc-alert-classifier:2.0` serves the image locally.

## Coding Style & Naming Conventions

Use four-space indentation, `snake_case` modules/functions, `PascalCase` classes, and `UPPER_SNAKE_CASE` constants. Follow existing type hints and module/function docstrings. Keep routes thin and preprocessing logic in dedicated modules. No formatter or linter is configured; match surrounding code.

## Testing Guidelines

Run standard-library `unittest` with `python -m unittest discover -s tests -v`. Tests use temporary logs and a fake model registry. No coverage threshold is configured. With the server running, smoke-test the batch endpoint:

```powershell
Invoke-RestMethod -Method Post -Uri http://localhost:8000/predict/batch -ContentType 'application/json' -InFile .\sample_batch.json
```

Verify successful responses contain `_id`, `tenant`, `model_version`, and `rate` (true-positive probability). Check missing tenants and versions, unknown tenants and versions, insufficient fields, and mixed-validity batches; preserve result order and per-alert errors. Name regression files `tests/test_*.py`.

## Commit & Pull Request Guidelines

History uses short subjects such as `add readme`; no enforced prefix convention or PR template exists. Write concise, action-oriented subjects. PRs should explain behavior changes, link relevant issues, record validation commands/results, and include request/response examples for API changes. Update documentation when contracts or configuration change.

## Configuration & Model Integrity

Environment variables override local `.env` settings. Keep secrets and unsanitized SIEM data out of commits. Preserve dependency pins and training-time feature order. Read tenants from `raw_data.tenant`, the required model version from `raw_data.model_version`, and features only from `events[]`; exclude resolution labels. Load only trusted pickle artifacts whose manifest checksums match, and never fall back to another version. New tenants and versions are picked up without a restart.
