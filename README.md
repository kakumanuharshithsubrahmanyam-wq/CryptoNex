# CryptoNex

## Overview

CryptoNex is a platform for post-quantum cryptography migration and crypto-agility. This repository contains the Phase 0 foundation: a runnable API, a runnable web shell, configuration, database setup, and tests. Cryptographic scanning and later product features are not implemented.

## Current Phase

Phase 0 — Foundation

The API exposes a health check. The web app reports whether that health check succeeds. A `Project` table is created at startup so later phases can persist data. No scanner, inventory, or migration behavior exists yet.

## Architecture

The backend and frontend are separate applications.

- The backend is a FastAPI service. Route handlers stay thin and call services. Settings, logging, database sessions, and API errors live in dedicated modules.
- The frontend is a React application. It reads the API origin from `VITE_API_BASE_URL` and calls the backend through a small API client.
- The browser talks to the API directly. CORS allows only the origins listed in `CORS_ORIGINS`.

Later phases can add routes, services, and models beside this layout without changing the split between the two applications.

## Technology Stack

- Python 3.11+
- FastAPI
- Pydantic v2
- Pydantic Settings
- SQLAlchemy 2
- SQLite (local development)
- Uvicorn
- pytest
- httpx
- httpx2 (used by the current Starlette test client)
- React
- TypeScript
- Vite

## Project Structure

```text
.
├── backend/
│   ├── app/
│   │   ├── api/v1/          # versioned HTTP routes
│   │   ├── core/            # settings, logging, database, errors
│   │   ├── models/          # SQLAlchemy models
│   │   ├── schemas/         # API request and response models
│   │   ├── services/        # logic used by routes
│   │   └── main.py          # application factory
│   ├── tests/
│   ├── requirements.txt
│   └── requirements-dev.txt
├── frontend/
│   └── src/
├── samples/
├── docs/
├── scripts/
├── .env.example
├── .gitignore
└── README.md
```

## Backend Setup

Requires Python 3.11 or newer. From the repository root:

```bash
cd backend
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.txt -r requirements-dev.txt
uvicorn app.main:app --reload --host 127.0.0.1 --port 8000
```

If `python3` is older than 3.11, create the virtual environment with a newer interpreter, for example `python3.13 -m venv .venv`.

The health check is `GET http://127.0.0.1:8000/api/v1/health`.

Startup creates the SQLite schema. Copy `../.env.example` to `../.env` or `backend/.env` when you want file-based settings. Environment variables override those files.

## Frontend Setup

From the repository root:

```bash
cd frontend
npm install
cp .env.example .env
npm run dev
```

The dev server prints a local URL, usually `http://localhost:5173`. The page calls `GET /api/v1/health` and shows **CryptoNex API Connected** when the backend responds. If the backend is down or the base URL is missing, the page shows a connection error.

## Environment Variables

Backend (process environment or `.env`):

| Variable | Purpose | Default |
| --- | --- | --- |
| `DATABASE_URL` | SQLAlchemy database URL | `sqlite:///./cryptonex.db` |
| `CORS_ORIGINS` | Comma-separated allowed browser origins | `http://localhost:5173,http://127.0.0.1:5173` |
| `ENVIRONMENT` | Runtime name, such as `development`, `test`, or `production` | `development` |
| `LOG_LEVEL` | `DEBUG`, `INFO`, `WARNING`, `ERROR`, or `CRITICAL` | `INFO` |

When `ENVIRONMENT=production`, `CORS_ORIGINS` must be an explicit list. An empty value or `*` fails startup.

Frontend:

| Variable | Purpose |
| --- | --- |
| `VITE_API_BASE_URL` | API origin, for example `http://localhost:8000` |

Vite reads this variable at dev-server and production-build time. Do not commit `.env`.

## Testing

Backend tests, from `backend` with the virtual environment activated:

```bash
pytest
```

Frontend type check and production build, from `frontend`:

```bash
npm run typecheck
VITE_API_BASE_URL=http://localhost:8000 npm run build
```

## Git/GitHub Development Workflow

The working branch is `main`. `origin` is the public GitHub repository:

https://github.com/kakumanuharshithsubrahmanyam-wq/CryptoNex

1. Create a branch for each change.
2. Keep secrets, virtual environments, `node_modules`, local databases, and build output out of Git. `.env` is ignored. Use `.env.example` and `frontend/.env.example` as templates.
3. Run `pytest` in `backend` and `npm run typecheck` plus `npm run build` in `frontend` before pushing.
4. Commit on the branch and open a pull request against `main`.

## Security Baseline

- The API does not accept file uploads and does not run shell commands.
- Request bodies are validated with Pydantic where a route accepts input.
- Error responses use one JSON envelope and do not include stack traces or exception text.
- Logs record the environment name, log level, and exception type. They do not record database URLs, tokens, or request bodies.
- CORS is an explicit allowlist. Production configuration rejects unrestricted origins.
