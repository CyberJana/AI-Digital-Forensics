# AI Digital Forensics

Foundation for a hybrid local-lab and cloud digital forensics investigation platform. The project is being implemented in controlled milestones; the current milestone provides the application skeleton and health checks only.

## Repository layout

- `backend/` — Python API package and tests.
- `frontend/` — Next.js dashboard.
- `docs/ARCHITECTURE.md` — proposed architecture, dependencies, deployment strategy, roadmap, and risks.

## Development

### Backend

Requires Python 3.12 or newer.

```powershell
cd backend
python -m pip install -e ".[dev]"
python -m uvicorn digital_forensics.main:app --reload
```

The API health endpoint is `http://127.0.0.1:8000/health`; OpenAPI documentation is at `http://127.0.0.1:8000/docs`.

Run backend tests from `backend/`:

```powershell
python -m pytest
```

### Frontend

Requires Node.js 20.9 or newer and npm.

```powershell
cd frontend
npm install
npm run dev
```

The dashboard is available at `http://localhost:3000`. The UI is currently a foundation shell and does not yet connect to the API.

## Scope and limitations

No evidence processing, authentication, persistence, external integrations, or deployment is implemented yet. Do not use this foundation with real evidence or for production investigations. See the architecture and roadmap in `docs/ARCHITECTURE.md`.
