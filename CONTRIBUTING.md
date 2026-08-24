# Contributing to PRAHARI

Thank you for your interest in PRAHARI — Behavioural Boot Attestation with Post-Quantum Signing.

## Development Workflow

1. Fork and clone the repository.
2. Install in editable mode:
   ```bash
   pip install -e .
   ```
3. Run the test suite:
   ```bash
   make test  # or: python -m unittest discover tests
   ```
4. Run the demo:
   ```bash
   make demo  # or: python -m prahari.cli demo boots/
   ```

## Code Standards

- Follow PEP 8 guidelines.
- Ensure all new detection or parsing features include unit tests in `tests/`.
- Maintain inspectable, zero-black-box decision models.

## Security Disclosures

Please report security issues responsibly via GitHub Security Advisories or by contacting the team directly.
