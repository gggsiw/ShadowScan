# ShadowScan

A modern, GUI-first web application auditing toolkit focused on safe, authorized testing. The toolkit bundles a large collection of passive and active checks in a clean desktop interface and exports results to JSON.

## Highlights
- Clean, app-like interface with animated status and progress
- 140+ modular checks across injection, misconfig, discovery, transport, and client-side risks
- Fast multi-threaded scanning with stop/cancel support
- JSON report export
- Credits view inside the app

## Requirements
- Python 3.9+
- `pip`

## Install
```bash
python -m venv venv
venv\Scripts\activate
pip install -r requirements.txt
```

## Run
```bash
python shadowscan.py
```

## Usage
- Enter a target URL with `http://` or `https://`
- Select modules or use `Select All`
- Click `Run Audit`
- Export results with `Export JSON`

## Notes
- Use only on targets you own or have explicit permission to test.
- Some checks are heuristic and may require manual verification.

## Credits
- Arjun Bohara

## SPECIAL THANKS FOR TESTING OUR TOOL
- IHA089
- Coding Chat Room
