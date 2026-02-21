# ASM Notebook (Passive)

A small, **passive-only** Attack Surface Management (ASM) notebook you can run from the CLI.  
It stores results per company and keeps scan history in SQLite for later review/export.

---

## What it does (today)

- Multi-company inventory (slug + name + root domain(s))
- Passive subdomain discovery via Certificate Transparency (crt.sh) with scope filtering
- DNS enrichment (A / AAAA / CNAME / MX / NS)
- Stores scan results + artifacts in SQLite
- Exports structured JSON for reporting or downstream analysis

> This project intentionally avoids invasive probing and focuses on publicly available signals only.

---

## Requirements

- Python 3.13+
- Poetry
- Network access (for crt.sh + DNS resolution)

---

## Install

```powershell
# From repo root
poetry install
```

---

## CLI Usage

Show help:

```powershell
poetry run python -m asm_notebook.cli --help
```

### Companies

Add a company (use domains you own or have authorization for):

```powershell
poetry run python -m asm_notebook.cli company add myco "My Company" --domain example.com
```

List companies:

```powershell
poetry run python -m asm_notebook.cli company list
```

Show company details:

```powershell
poetry run python -m asm_notebook.cli company show myco
```

Update domains (replace existing domains):

```powershell
poetry run python -m asm_notebook.cli company set-domain myco --domain example.com
```

---

### Scans

Run a passive scan:

```powershell
poetry run python -m asm_notebook.cli scan run myco
```

List scans:

```powershell
poetry run python -m asm_notebook.cli scan list myco
```

Export a scan to JSON:

```powershell
poetry run python -m asm_notebook.cli scan export 4 --out-json scan4.json
```

---

## Data & Storage

- The app uses a local SQLite database (default: `asm_notebook.sqlite3` in the repo root).
- Scan artifacts are stored as JSON in the database and can be exported via `scan export`.
- The database file is intentionally excluded from Git.

---

## Roadmap (Planned)

- FastAPI backend (REST API for companies, scans, artifacts, and scan execution)
- React frontend (browser UI for inventory + scan history + artifact views)
- Optional passive integrations (Shodan / Censys APIs)
- Scan diffing ("new assets detected")
- Docker packaging for reproducible demo/deploy

---

## Safety / Scope

This repository is intended for authorized security assessment and learning.

Even passive reconnaissance can be sensitive.  
Only analyze domains you own or have explicit permission to assess.

---

## License

MIT (see `LICENSE`).