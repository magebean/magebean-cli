# Contributing to Magebean CLI

Use a focused branch and explain the observed problem, final behavior, validation and limitations.

## Source of truth

- Primary definitions: src/Rules/requirements/magebean-catalog.json, asvs-catalog.json and pci-catalog.json. Keep the compatibility aggregate internal-catalog.json consistent.
- Native profile membership/default context: src/Rules/requirements/internal-profiles.json.
- Engine and adapters: src/Engine, src/Console and src/Agent.
- Regression tests: tests/*Test.php, with isolated fixtures and explicit evidence expectations.

A rule should report an inspectable current condition, its scope and uncertainty, and a concrete fix/recheck. Missing evidence is not PASS or a vulnerability. Keep explicit policy observations distinct from exploitability claims. Preserve stable identities, criterion history and normative source-family boundaries.

## Validation and documentation

```sh
php tests/run.php
php tools/update-baseline-doc.php
php tools/update-baseline-doc.php --check
python3 tools/check-docs.py
```

Update current docs under docs/guides, docs/reference or docs/standards. Baseline v1 is generated from runtime catalogues; do not edit its inventory by hand. Superseded plans/reviews belong in docs/archive, with an index and working references. Do not rewrite historical counts/outcomes as current facts or delete evidence used by regression tools. Review intentional compatibility snapshot changes before recording them.

For packaged changes, use [release packaging](docs/reference/release-packaging.md). Builds qualify a local candidate; they do not deploy or modify production Console data. Keep vendor, build staging and private project/agent configuration out of commits. The project is licensed under [MIT](LICENSE).
