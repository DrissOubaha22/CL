# Aegis — intel core

Vulnerability Threat Intelligence platform. This repository currently holds
**phase 1** of the build order in the technical specification (§14): the
deterministic feed ETL and the shared, per-CVE intel store.

Aegis correlates real-world exploitation intelligence against each client's
exposed software and reports what is actually at risk. It does **not** run
vulnerability scans for detection coverage — it consumes the client's existing
scanner output as one inventory source among several.

## What phase 1 contains

| Area | Status |
| --- | --- |
| Shared per-CVE intel store (§9) | built |
| Deterministic ETL: CISA KEV, FIRST EPSS, NVD (§4.1) | built |
| CPE 2.3 normalisation and vendor version ranges (§3.2, §5.2) | built |
| `exploit_status` derivation (§7.1) | built |
| Scheduling, journalling, CLI (§10 steps 2 and 10) | built |
| VulnCheck KEV, Exploit-DB/Metasploit/Nuclei (§4.1) | reserved, not implemented |
| LLM extraction of vendor advisories (§4.2) | phase 4 |
| Inventory, matching, verification, scoring, bulletins | phases 2–5 |

Phase 1 is done when "intel records build & refresh per CVE" (§14). That is
what `tests/integration/test_pipelines.py` asserts.

## Design decisions worth knowing

**The merged record is derived, never patched.** Each source writes an
`intel_contribution` row holding only the fields it owns; `intel_record` is a
pure function of those rows. This buys idempotence (a re-run cannot drift a
record) and retraction: when CISA removes a CVE from KEV, dropping that
contribution and re-deriving clears `on_kev`, instead of leaving behind a
claim no source still makes.

**Field ownership is explicit.** `aegis.intel.derive.FIELD_OWNERS` lists which
sources may write which field, in precedence order. A feed drifting outside
its remit cannot silently overwrite better data — NVD reporting an EPSS score
is ignored, because EPSS owns that field.

**Exploitation evidence is additive, severity is not.** `public_exploit` is
true if *any* source proves exploit code exists; one source not knowing about
it does not cancel another's finding. Single-owner fields like `cvss` take the
highest-precedence source that has an opinion.

**Versions are compared, not string-matched.** `7.4.10 > 7.4.9`, `2.0.0-beta <
2.0.0`, and `7.4.2b > 7.4.2` — a separator-introduced marker word is a
pre-release, a digit-glued letter is a vendor patch level. An unorderable
version raises rather than guessing, which is what lets the matching engine
downgrade confidence instead of asserting a match (§5.2).

**No client data reaches a feed.** The intel path has no access to tenant data
at all, and the HTTP client sends a generic user agent. This is the structural
half of the AI data boundary in §11; the LLM half arrives in phase 4.

## Layout

```
src/aegis/
  config.py            settings (env-prefixed AEGIS_), feed endpoints, budgets
  logging.py           structlog setup
  cli.py               `aegis intel sync | show | status`, `aegis config`
  tasks.py             Celery app + beat schedule
  core/
    enums.py           ExploitStatus, FeedSource, RunStatus
    cpe.py             CPE 2.3 formatted-string binding
    versions.py        vendor/semver ordering and range tests
  db/
    base.py            engine, session scope, declarative base (intel schema)
    types.py           StrEnum <-> VARCHAR column type
    models/intel.py    intel_record, intel_contribution, intel_source,
                       affected_cpe, feed_run
  intel/
    schemas.py         validated feed -> store contract, content digests
    derive.py          field ownership, merge, exploit_status derivation
    store.py           upsert, rebuild, retract
    http.py            retries, rate limiting
    runner.py          run one or all pipelines
    feeds/             kev.py, epss.py, nvd.py, registry.py
migrations/            Alembic, intel schema only
```

## Running it

```bash
docker compose up -d postgres redis
```

```bash
pip install -e ".[dev]"
```

```bash
cp .env.example .env
```

```bash
alembic upgrade head
```

Then sync the feeds. KEV and EPSS need no credentials; NVD works without an
API key at 5 requests per 30 seconds, and much faster with one.

```bash
aegis intel sync
```

```bash
aegis intel sync --source nvd
```

```bash
aegis intel show CVE-2026-104286
```

```bash
aegis intel status
```

Under Celery, KEV polls hourly, NVD every six hours incrementally, and EPSS
once a day:

```bash
celery -A aegis.tasks worker -Q intel -l info
```

```bash
celery -A aegis.tasks beat -l info
```

## Tests

Unit tests need nothing. Integration tests need a live PostgreSQL, because the
store relies on JSONB, partial indexes and schemas — faking it with SQLite
would test something the product does not run on.

```bash
pytest tests/unit -q
```

```bash
AEGIS_TEST_DSN=postgresql+psycopg://aegis:aegis@localhost:5432/aegis_test pytest -q
```

`tests/integration/test_migrations.py` builds a throwaway database, applies
`alembic upgrade head`, and diffs the result against the models — so a model
change that forgets its migration fails CI.

## What phase 2 needs from this

The matching engine joins tenant inventory against `affected_cpe`, which is
indexed on `(vendor, product)` and carries the version bounds unflattened.
`aegis.core.cpe.same_product` and `aegis.core.versions.version_in_range`
already implement the two halves of the match predicate in §5.1; the matcher
supplies the inventory side and the false-positive flags of §5.3.
