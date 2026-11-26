# Aegis — intel core

Vulnerability Threat Intelligence platform. This repository holds
**all five phases** of the build order in the technical specification (§14):
the deterministic feed ETL and shared intel store, per-tenant inventory and
matching, exposure verification and scoring, LLM advisory extraction and the
bulletin pipeline, then tenancy hardening, the tenant API and delivery.

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
| Exposure verification (§6.1, §6.2, §6.3) | phase 3 |
| Scoring engine and SLA windows (§7.1, §7.2) | phase 3 |
| LLM extraction of vendor advisories (§4.2) | phase 4 |
| Privacy-safe bulletin drafting and routing (§8) | phase 4 |
| RBAC, SSO, secrets, append-only audit (§11) | phase 5 |
| Database-enforced read-only shared intel (§11) | phase 5 |
| Slack / Teams delivery (§12) | phase 5 |
| Tenant-scoped REST API (§12) | phase 5 |
| Scheduling, journalling, CLI (§10) | phases 1-5 |
| VulnCheck KEV, Exploit-DB/Metasploit/Nuclei (§4.1) | reserved, not implemented |
| Scanner / ASM / cloud / CMDB adapters (§3.1) | interface only |
| Jira / ServiceNow / email (§12), web dashboard (§13) | not built |

The phase criteria of §14 are what the integration tests assert: "intel
records build & refresh per CVE" in `tests/integration/test_pipelines.py`,
"matches produced per tenant, pre-plugin" in
`tests/integration/test_matching.py`, "verified, tiered cases; false
positives cut" in `tests/integration/test_scoring.py::TestFullCycle`, and
"privacy-safe auto/review bulletin pipeline" in
`tests/integration/test_bulletin_pipeline.py`, and "isolated tenants;
delivery wired" in `tests/integration/test_api.py::TestCrossTenant`,
`tests/integration/test_isolation.py` and
`tests/integration/test_delivery.py`.

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

**A tier explains itself.** Scoring stores both what §7.2 produced and what
the verification gate left, with every input and cap reason beside it. A case
sitting at Medium records that it would be Critical and which caveat is
holding it there — a tier nobody can argue with is a tier nobody acts on.

**Verification is bounded by construction.** One host, one port, per match;
no ranges, no payloads, nothing globally unroutable, and paced per host. The
boundary §6.2 describes lives in `verification/scope.py` rather than in the
discipline of each call site.

**The model never sees client data, and that is checked twice.** Everything
sent to a model is a `PublicPayload` built only from the shared intel store
or a fetched public page, and a runtime guard refuses any payload containing
a tenant identifier. There is no scrub function on purpose: redacting a leak
hides the bug that produced it.

**A claim without a citation does not exist.** Model-extracted facts are
discarded outright when unsourced, and a high-stakes claim backed by a
single publisher is forced to low confidence and queued for a human (§4.2).

**Isolation has three layers.** The schema stops a tenant reading another's
rows; RBAC stops reading a tenant you hold no role in; database grants stop
a tenant worker writing the shared intel every tenant depends on. The third
is the one schema separation cannot do, because the intel tables are
deliberately in reach.

**The audit log cannot be rewritten by the application.** A trigger raises
on UPDATE and DELETE. A log the application merely promises not to rewrite
is a log that anyone with application access can rewrite.

**Unconfigured means closed.** With no SSO issuer configured the API refuses
to start, rather than serving requests it cannot authenticate.

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
  verification/
    scope.py           what §6.2 allows a probe to touch
    probes.py          reachability, TLS, banner, WAF detection (§6.1)
    engine.py          observations -> verdict, audit trail (§6.2)
  scoring/
    tiering.py         §7.2's rule, and the gates that cap it
    engine.py          scoring a tenant's matches
    runner.py          verify-and-score per tenant
  ai/
    privacy.py         the AI data boundary (§8.1): what may be sent, checked
    client.py          model access, injection hardening, zero retention (§8.3)
    prompts.py         the system prompts, reviewable as text
  intel/extraction/    advisory fetch, output schema, the two-source rule (§4.2)
  bulletins/
    drafting.py        public-facts-only drafting (§8.1)
    templates.py       template injection: where client fields enter
    routing.py         the automation tiers (§8.2)
    engine.py          a bulletin per scored match
    runner.py          per-tenant orchestration
  auth/
    rbac.py            roles, permissions, principals (§11)
    audit.py           the append-only trail, and the access check that writes it
    oidc.py            SSO token verification (§11)
    secrets.py         the vault seam, and rotation staleness (§11)
  delivery/
    formatters.py      Slack and Teams payloads (§12)
    sender.py          idempotent webhook delivery
    runner.py          per-tenant orchestration
  api/
    app.py             the application factory
    deps.py            authenticate, authorise, audit - in one place
    routes.py          tenant-scoped endpoints (§12)
    schemas.py         explicit response shapes
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

Then verify exposure and turn matches into tiered cases:

```bash
aegis case assess --slug acme
```

```bash
aegis case list acme
```

```bash
aegis case show acme 1
```

Then draft and route the client-facing advisories:

```bash
aegis bulletin generate --slug acme
```

```bash
aegis bulletin list acme
```

```bash
aegis bulletin show acme 1
```

`--draft-only` shows just the half a model wrote, which is the audit
evidence for §8.1. A queued bulletin is released by an analyst:

```bash
aegis bulletin issue acme 1 --analyst "j.martin"
```

Register where issued bulletins go, and send them (§12). The webhook URL
lives in the vault; only its name is stored:

```bash
aegis delivery add acme --label "SOC on-call" --channel slack --secret-name slack_soc
```

```bash
aegis delivery send --slug acme
```

Make the shared intel store read-only to tenant workers (§11). Prints the
SQL for review by default:

```bash
aegis db grants --apply --create-roles
```

Serve the tenant API (§12). It refuses to start without SSO configured:

```bash
aegis serve --host 0.0.0.0 --port 8000
```

Read the audit trail, or just the refused attempts:

```bash
aegis audit tail --denials-only
```

Drafting uses `claude-opus-5-5` by default. Set `AEGIS_LLM_ENABLED=false` to
run without a model — bulletins are then drafted deterministically from the
same facts and say so in `drafted_by`.

`case assess` sends real traffic: one TCP connect, one TLS handshake and one
HTTP request per match, to the single host and port that match names. Set
`AEGIS_VERIFICATION_ENABLED=false` to score without probing — every case then
stays capped at Medium, since nothing has been confirmed.

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

## What phase 4 needs from this

Bulletin generation (§8) drafts from the public intel record and merges
tenant specifics afterwards, inside the Aegis boundary. The automation tiers
of §8.2 key on `Score.auto_escalatable`: exploited, patch available and
exposure verified is exactly the case that reaches it `True`.

Two fields are already consumed but have no producer yet, both arriving with
the LLM advisory extraction of §4.2: `intel_record.vendor_confirmed`, which
forces High/Critical before CISA lists a CVE, and
`intel_record.config_dependent`, which flags a match config-dependent.
Adding that pipeline needs no change to the store, the matcher or the scorer.

Implementation notes, keyed to the specification section by section:
[`docs/intel-core.md`](docs/intel-core.md),
[`docs/inventory-and-matching.md`](docs/inventory-and-matching.md),
[`docs/verification-and-scoring.md`](docs/verification-and-scoring.md).
