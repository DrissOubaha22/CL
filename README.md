# Aegis — intel core

Vulnerability Threat Intelligence platform. This repository holds
**phases 1 and 2** of the build order in the technical specification (§14):
the deterministic feed ETL and shared intel store, then per-tenant inventory
and the matching engine.

Aegis correlates real-world exploitation intelligence against each client's
exposed software and reports what is actually at risk. It does **not** run
vulnerability scans for detection coverage — it consumes the client's existing
scanner output as one inventory source among several.

## What is built

| Area | Status |
| --- | --- |
| Shared per-CVE intel store (§9) | phase 1 |
| Deterministic ETL: CISA KEV, FIRST EPSS, NVD (§4.1) | phase 1 |
| CPE 2.3 normalisation and vendor version ranges (§3.2, §5.2) | phase 1 |
| `exploit_status` derivation (§7.1) | phase 1 |
| Schema-per-tenant isolation (§1, §11) | phase 2 |
| Inventory ingestion and CPE resolution (§3.1, §3.2) | phase 2 |
| Matching engine (§5.1, §5.2) | phase 2 |
| False-positive controls (§5.3) | phase 2 |
| Scheduling, journalling, CLI (§10) | phase 1 + 2 |
| VulnCheck KEV, Exploit-DB/Metasploit/Nuclei (§4.1) | reserved, not implemented |
| Scanner / ASM / cloud / CMDB adapters (§3.1) | interface only |
| Exposure verification (§6), scoring (§7) | phase 3 |
| LLM extraction (§4.2), bulletins (§8) | phase 4 |
| RBAC/SSO, audit, ticketing, portal (§11, §12) | phase 5 |

The phase criteria of §14 are what the integration tests assert: "intel
records build & refresh per CVE" in `tests/integration/test_pipelines.py`, and
"matches produced per tenant, pre-plugin" in
`tests/integration/test_matching.py`.

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

**Tenant isolation is physical.** Per-tenant tables live in `tenant_<slug>`
schemas and are reached through a `schema_translate_map`, not a `tenant_id`
filter. A query issued without a tenant scope does not return the wrong rows —
it fails, because the placeholder schema does not exist.

**Flags caveat a match, they never suppress it.** A suppressed match is one
nobody can review. A backported distro package still produces a match; it is
flagged, capped at low confidence, and barred from auto-escalation (§5.3).

## Layout

```
src/aegis/
  config.py            settings (env-prefixed AEGIS_), feed endpoints, budgets
  logging.py           structlog setup
  cli.py               aegis intel | tenant | inventory | match | config
  tasks.py             Celery app + beat schedule
  core/
    enums.py           vocabulary: exploitation, exposure, confidence, flags
    cpe.py             CPE 2.3 formatted-string binding
    versions.py        vendor/semver ordering and range tests
    classification.py  product class and match confidence (§3.3)
  db/
    base.py            engine, sessions, the three declarative bases
    types.py           StrEnum <-> VARCHAR column type
    ordering.py        ORDER BY enum rank, not alphabetically
    tenancy.py         schema-per-tenant sessions and provisioning
    tenant_migrations.py   per-tenant migration fan-out
    models/
      intel.py         intel_record, intel_contribution, intel_source,
                       affected_cpe, feed_run
      control.py       tenant registry
      tenant.py        asset, asset_cpe, match, match_run
  intel/
    schemas.py         validated feed -> store contract, content digests
    derive.py          field ownership, merge, exploit_status derivation
    store.py           upsert, rebuild, retract
    http.py            retries, rate limiting
    runner.py          run one or all pipelines
    feeds/             kev.py, epss.py, nvd.py, registry.py
  inventory/
    schemas.py         import contract; exposure derived from evidence
    normalise.py       product -> one or more CPE strings
    loader.py          JSON / CSV import files
    store.py           asset upsert, retirement
  matching/
    engine.py          the cross-schema join and version test (§5.1)
    flags.py           false-positive controls (§5.3)
    runner.py          per-tenant orchestration
migrations/            Alembic: intel + control schemas
migrations_tenant/     Alembic: per-tenant schemas, fanned out per tenant
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

Then onboard a tenant and match its inventory:

```bash
aegis tenant create acme --name "Acme Corp"
```

```bash
aegis inventory import acme inventory.csv
```

```bash
aegis match run --slug acme
```

```bash
aegis match list acme
```

An inventory file is JSON or CSV with one row per discovered product. The
`evidence` column is what sets exposure — there is no way to declare it
directly (§3.2):

```csv
hostname,product,version,evidence,criticality,source
vpn.acme.test,FortiOS,7.4.1,answered_publicly,high,asm
db1.acme.test,openssl,3.0.2,seen_internally,medium,scanner
```

After a schema change, each tenant schema is migrated independently:

```bash
aegis tenant upgrade
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
both migration histories, and diffs the result against the models — so a model
change that forgets its migration fails CI.

## What phase 3 needs from this

Exposure verification (§6) fills `asset.exposure_verified_at`, which clears
the `unverified` flag that currently sits on every match.

Scoring (§7) reads a match's `confidence` and `flags` together with the
asset's `exposure_class` and `criticality` and the intel record's
`exploit_status`, `epss` and `ransomware`. `MatchVerdict.auto_escalatable` is
the single predicate for "may this be raised without a human".

Implementation notes, keyed to the specification section by section, are in
[`docs/intel-core.md`](docs/intel-core.md) and
[`docs/inventory-and-matching.md`](docs/inventory-and-matching.md).
