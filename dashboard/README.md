# Shadow AI · IaC Security Dashboard

A premium dark-mode HTML/CSS/JS dashboard + Flask backend for the Shadow AI IaC security pipeline.

## Files

```
dashboard/
├── index.html          ← Main dashboard UI (6 pipeline phases)
├── style.css           ← Dark glassmorphism design system
├── app.js              ← Frontend logic (scan, intent render, IaC input)
├── server.py           ← Flask backend (/scan endpoint)
└── requirements.txt    ← Python deps (flask, flask-cors)

v2.py                   ← Prompt scanner + negation-aware intent extractor
```

## How to Run

### 1. Install backend dependencies
```bash
pip install flask flask-cors
# (llm-guard and torch are already installed in your venv)
```

### 2. Start the Flask server
```bash
cd path/to/new/dashboard
python server.py
```

### 3. Open in browser
```
http://localhost:5000
```

## Pipeline Phases in the Dashboard

| Phase | Feature | Notes |
|-------|---------|-------|
| 1 | **Prompt Scanner** | Text area → "Proceed to Prompt Scan" → runs LLM Guard |
| 1 (output) | **Scan Results** | Shows PII/Secrets/Injection scores + sanitized prompt |
| 2 | **Intent Extractor** | Negation-aware (not, without, disable, no, never, don't…) |
| 3 | **IaC Script Input** | Manual paste — unlocked only when scan passes |
| 4 | **Attack Graph** | Placeholder space for future engine output |
| 5 | **Risk Score** | Placeholder with score breakdown layout |
| 6 | **Deploy Decision** | Approve / Reject buttons + pre-deploy checklist |

## Negation Keywords Handled

The intent extractor in `v2.py` now uses a **sliding 6-word window** look-behind to detect negation. Recognised negation words:

> `not` · `without` · `disable` · `no` · `never` · `don't` · `do not` · `avoid` · `skip` · `turn off` · `remove` · `disallow` · `block` · `prevent` · `except` · `unless`

Example: *"Deploy without encryption"* → `encryption.enabled = false`, `encryption.disabled = true`
