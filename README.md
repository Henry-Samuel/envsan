# envsan

Audit environment variables for secrets, unsafe values, and policy violations.

## About

`envsan` scans local environment variables and reports sensitive names, unusually long values, and policy issues in a readable CLI or JSON format. It is designed for local debugging, container audits, and CI environment hardening.

## Features

- Secret-like variable name detection: `SECRET`, `API_KEY`, `PASSWORD`, `TOKEN`, and related names.
- Long value heuristic: flags values that may represent sensitive tokens despite generic names.
- Severity classification: `CRITICAL`, `HIGH`, `MEDIUM`, `LOW`.
- JSON and human-readable output.
- Custom policy rules: supply your own name patterns and severity mapping.

## Installation

```bash
python -m pip install envsan
```

Or try it directly from source:

```bash
python -m envsan.cli
```

## Usage

### Basic scan

```bash
python -m envsan.cli
```

Exit code is nonzero when there are `MEDIUM` or higher findings.

### JSON output

```bash
python -m envsan.cli --json
```

### Programmatic

```python
from envsan import EnvironmentPolicy, scan_environment

policy = EnvironmentPolicy()
findings = scan_environment(policy=policy)
for finding in findings:
    print(finding)
```

## Project structure

```
envsan/
  src/envsan/
    __init__.py
    cli.py
    models.py
    policy.py
    scanner.py
  tests/
    test_policy.py
    test_scanner.py
  pyproject.toml
  README.md
```

## Limitations

- Default heuristic can flag benign long values; tune `exclude` when needed.
- Rule coverage is intentionally small; add custom policies for workflows.

## License

MIT
