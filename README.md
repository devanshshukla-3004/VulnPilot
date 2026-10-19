# VulnPilot
### Explainable Vulnerability Prioritization & Remediation Platform

VulnPilot is a defensive security application for importing asset and vulnerability records, prioritizing remediation with an explainable heuristic model, and tracking remediation history.

> **Status:** Initial MVP scaffold. The scoring model is a prioritization aid, not a probability of compromise or a replacement for CVSS, vendor advisories, or professional risk assessment.

## MVP capabilities
- FastAPI REST API with OpenAPI docs
- SQLite persistence for assets, vulnerabilities, and status-change history
- Deterministic, explainable prioritization score
- CSV/JSON import with validation and duplicate handling
- Remediation status workflow and audit history
- React dashboard (frontend scaffold)
- Automated backend tests and GitHub Actions

## Quick start (Windows PowerShell)
```powershell
py -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
uvicorn backend.app.main:app --reload
```
Open `http://127.0.0.1:8000/docs` for API documentation.

Run tests:
```powershell
python -m pytest -q
```

## Import data
Use `POST /api/import/json` with a JSON body containing `assets` and `vulnerabilities`. See `samples/demo_data.json`.

## Scoring model
The initial score combines CVSS severity, asset criticality, internet exposure, exploit availability, and remediation state. Weights and mapping are explicit in `backend/app/risk.py`; scores are deterministic and capped at 100. The model is a transparent internal heuristic and is not calibrated to predict exploit likelihood.

## Safety & limitations
- Designed for authorized vulnerability-management workflows.
- Does not scan hosts, exploit vulnerabilities, or change target systems.
- Sample data is synthetic.
- External CVE feed integration is not enabled in this initial version.
- Asset exposure and exploit status are user-supplied fields and should be verified.
- This is an MVP, not a certified compliance or enterprise vulnerability management product.

## Project layout
```
backend/app/      API, database, models, scoring
tests/            automated tests
samples/          synthetic demo dataset
frontend/         React + TypeScript dashboard scaffold
.github/workflows automated tests
```
