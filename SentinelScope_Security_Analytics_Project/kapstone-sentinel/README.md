# SentinelScope Security Analytics

A user-friendly cybersecurity log analysis prototype for the Kapstone Technological Services LLP AI/ML Developer Intern technical assessment. It demonstrates supervised ML classification, rule-supported risk scoring, alert correlation, indicative compliance mapping, CSV ingestion, API validation, and report export.

> **Important:** This is an educational assessment prototype. The included logs are synthetic. Do not use its output as proof of compromise, a production security control, or an audit opinion. Validate all findings against source systems and your organization's approved framework scope.

## Features

- **ML detection:** TF-IDF text features + Logistic Regression trained on an included labeled dataset.
- **Evaluation:** reproducible stratified 75/25 held-out split; accuracy, suspicious-class precision/recall/F1, confusion matrix, and classification report.
- **Triage support:** severity-aware risk score, model probability, visible keyword rule indicators, evidence explanation, and recommended next steps.
- **Alert correlation:** suspicious events grouped by shared source IP or asset within a one-hour time window.
- **Compliance mapping:** indicative mappings to selected NIST CSF 2.0 / ISO/IEC 27001:2022 control references, with evidence and remediation guidance.
- **Data connector:** CSV upload endpoint and bundled sample dataset. CSV schema is validated before analysis.
- **Reporting:** downloadable JSON security report.
- **Dashboard:** responsive interface, search, risk/classification filters, event detail modal, dark mode, incident queue, model evaluation page.
- **API:** FastAPI endpoints with validation and basic error handling.

## Quick start (Windows)

1. Install Python 3.10 or newer from https://www.python.org/downloads/ (enable **Add Python to PATH** during setup).
2. Extract this ZIP file and open the `kapstone-sentinel` folder in VS Code.
3. Open Terminal → New Terminal, then run:

```powershell
py -m venv .venv
.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
pip install -r requirements.txt
uvicorn app.main:app --reload
```

If PowerShell blocks activation, run `Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass` in that terminal, then activate again. Alternatively, use Command Prompt and run `.venv\Scripts\activate.bat`.

4. Open http://127.0.0.1:8000 in your browser. API docs are at http://127.0.0.1:8000/docs.

## Quick start (macOS / Linux)

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
pip install -r requirements.txt
uvicorn app.main:app --reload
```

## API endpoints

| Method | Endpoint | Purpose |
|---|---|---|
| GET | `/api/health` | Service health |
| GET | `/api/sample-logs` | Return bundled sample logs |
| GET | `/api/dashboard` | Analyze sample logs and return metrics |
| POST | `/api/analyze` | Analyze JSON `{ "logs": [...] }` |
| POST | `/api/upload-csv` | Upload and analyze a CSV file (`multipart/form-data`, field `file`) |
| GET | `/api/model-metrics` | Train/evaluate model and return metrics |
| POST | `/api/report` | Return downloadable JSON report from `{ "logs": [...] }` |

### Input schema

Each event should include `timestamp`, `event_type`, `source_ip`, `asset`, `severity`, and `message`. `event_id` is optional. The CSV importer requires those six columns and accepts up to 5,000 rows / 5 MB. The JSON analyze API validates 1–5,000 events. Rows without a message are skipped.

Example API request:

```json
{
  "logs": [
    {
      "event_id": "EVT-1",
      "timestamp": "2026-10-16T08:10:00Z",
      "event_type": "authentication",
      "source_ip": "198.51.100.24",
      "asset": "vpn-gateway-01",
      "severity": "high",
      "message": "Multiple failed login attempts against admin account"
    }
  ]
}
```

## Project structure

```text
kapstone-sentinel/
├── app/
│   ├── main.py                 # FastAPI app and routes
│   ├── ml.py                   # Training and evaluation
│   ├── engine.py               # Detection, scoring, correlation, control mapping
│   └── static/
│       ├── index.html          # Dashboard structure
│       ├── styles.css          # Responsive UI / dark mode
│       └── app.js              # Frontend behavior and API integration
├── data/
│   ├── training_logs.csv       # Synthetic labeled training dataset
│   └── sample_logs.json        # Sample incident-like events
├── models/                     # Trained model artifact generated on first run
├── reports/                    # Reserved for saved reports
├── tests/
├── requirements.txt
└── README.md
```

## Model and evaluation details

The training data is synthetic and intentionally includes recognizable examples of routine and suspicious events. `app/ml.py` creates a TF-IDF + Logistic Regression pipeline, uses a stratified split with `random_state=42`, then evaluates the held-out split. The model artifact is generated at `models/security_log_model.joblib` on first use. Use `python -c "from app.ml import evaluate_model; print(evaluate_model())"` to print fresh metrics.

A suspicious probability is one signal, not a verdict. The engine combines the model prediction with event severity and explicit keyword indicators to create a transparent triage result. Because synthetic data may contain repeated templates and does not represent real enterprise telemetry, metrics can be optimistic and should not be compared directly with production systems.

## Correlation logic

The prototype groups suspicious events sharing a non-empty source IP or asset where timestamps fall within a one-hour span. Overlapping IP and asset groups are merged. This is a deterministic demonstration, not a full SIEM correlation engine; it does not establish causality or use threat-intelligence feeds.

## Compliance mapping

Control references are indicative associations selected for this demo. They include NIST CSF 2.0 and ISO/IEC 27001:2022 references. Review the official standard and organizational Statement of Applicability before making a formal compliance claim. The mappings are not a substitute for the licensed framework text, a risk assessment, or an auditor's judgment.

## Tests

Install dependencies first, then run:

```bash
python -m unittest discover -s tests -v
```

## Suggested assessment demo (5–7 minutes)

1. Open the dashboard and describe the included synthetic data.
2. Show the event explorer; filter suspicious events and inspect evidence for one high-risk event.
3. Open Incidents and explain the shared-IP / asset one-hour correlation rule.
4. Open Compliance Mapping and explain that references are indicative and need review.
5. Open Model Evaluation and explain the split, features, classifier, metrics, and limitations.
6. Import a CSV with the documented schema and export the JSON report.
7. Open `/docs` to demonstrate the backend API.

## GitHub submission checklist

- Include source code, dataset, README, and model artifact if you choose to commit it.
- Never commit passwords, access tokens, real user logs, secrets, or personally identifiable information.
- Add your own name and a brief explanation of what you personally implemented.
- Be ready to explain the classifier, metric definitions, correlation logic, limitations, and every major code path.

## Known limitations

- Synthetic training data; no real SIEM, EDR, cloud, or threat-intelligence connector is configured.
- Correlation is simple key/time grouping, not a production incident graph.
- Compliance mappings are heuristic and require human verification.
- No authentication or role-based access control; keep the server local and do not expose it publicly without adding security controls.
- The generated report uses the analyzed input and should be reviewed before external distribution.
