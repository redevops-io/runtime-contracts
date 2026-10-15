# Contributing

1. Fork, branch from `main`.
2. `pip install -e ".[dev]"`, then `python -m pytest -q` and `python scripts/docs_check.py`.
3. **Never rewrite a released golden hash**; follow [docs/release-discipline.md](docs/release-discipline.md).
4. Documentation claims: label any number with one of *Illustrative/synthetic*, *Internally reproduced*,
   *Externally reproduced*, *Field validated* and add a card under `docs/evidence/`. Do not claim
   conformance that `adoption/implementations.yaml` does not record.
5. Security issues: [SECURITY.md](SECURITY.md); no public issue.

Licence of contributions: see [LICENSE.md](LICENSE.md).
