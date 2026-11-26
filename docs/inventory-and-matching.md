# Inventory and matching — implementation notes

Reference notes for phase 2, keyed to *Aegis — Technical Specification v1.0*.

Phase 2 is done when "matches produced per tenant, pre-plugin" (§14): a client
is told about a vulnerability in software they already run, before their
scanner ships a detection plugin for it.

## 1. Tenant isolation is physical, not a `WHERE` clause

§1 lists "hard tenant isolation — schema- or database-per-tenant" as a design
principle, and §11 repeats it. That is implemented now rather than deferred to
phase 5, because retrofitting it later is a data migration, not a refactor.

The database is split three ways:

| Schema | Holds | Written by |
| --- | --- | --- |
| `intel` | shared per-CVE store | the ETL role only |
| `control` | tenant registry | provisioning |
| `tenant_<slug>` | inventory and matches | that tenant's workers |

Per-tenant models are declared once against the placeholder schema `tenant`
and resolved per session through SQLAlchemy's `schema_translate_map`
(`aegis.db.tenancy.tenant_session_scope`). One set of model classes, N
physically separate schemas.

§9 lists `tenant_id` on each per-tenant entity. Those columns are deliberately
**absent** here: with schema-per-tenant the column would be a constant within
each schema, and isolation would rest on every query remembering to filter by
it. Instead, a query issued without a tenant scope does not return the wrong
rows — it fails, because `tenant.asset` is not a real table. That is asserted
in `tests/integration/test_tenancy.py::test_an_unscoped_query_cannot_run`.

The cost is two migration histories: `migrations/` for the global schemas and
`migrations_tenant/` fanned out per tenant by `aegis tenant upgrade`. Each
tenant carries its own `alembic_version`, so one can lag or be migrated alone.
Provisioning runs that same history rather than `create_all`, so a tenant
created today and one created last year then migrated end up byte-identical.

## 2. Asset grain: `(host, product, port)`

Not `host` — a server running nginx and OpenSSH matches independently on each.
Not `(host, product, version)` either, which was the first attempt and was
wrong: a version bump then creates a *second* asset, leaves the vulnerable row
in place, and its match stays open forever. §9 lists `version` as a column on
the asset, which is what settles it. Patching a host now updates it in place,
and the next matching pass resolves the finding.

## 3. Exposure cannot be self-declared

§3.2: the exposure flag is "set from discovery evidence … not from a
self-declared field". That is enforced structurally rather than by review: an
`InventoryItem` states what discovery *observed*
(`answered_publicly`, `seen_internally`, `installed_on_endpoint`) and
`exposure_class` is derived. There is no way to pass `exposure_class` into an
import; the model rejects it.

Client-side software maps to `CLIENT_SIDE`, never `INTERNET`, whatever host it
sits on (§6.3).

## 4. CPE resolution emits several spellings on purpose

§3.2: "resolved to one or more CPE strings". The same product is spelled
differently by different publishers — `apache:http_server` and `apache:httpd`,
`nginx:nginx` and `f5:nginx` — and intel may name any of them. Emitting every
plausible spelling and joining on all of them is what stops a naming mismatch
from silently hiding a vulnerable asset.

Resolution runs in three passes, most to least reliable:

1. CPEs the source already supplied (scanners usually know) — trusted verbatim.
2. A curated alias table covering the §3.3 scope, including vendor-prefixed
   banner spellings (`Microsoft Exchange Server` → `microsoft:exchange_server`).
3. A slugified guess, marked as such. A guessed identity is capped below high
   confidence however the product classifies.

A production deployment should also import the official NVD CPE dictionary;
`known_product_keys()` is the same idea against the identities already present
in collected advisories.

## 5. The two-stage matcher

§5.1 states the logic as a nested loop over assets × affected CPEs. Run
literally that is a full cross product, so it executes in two stages with
identical semantics:

1. **SQL narrows** — one cross-schema join on `(part, vendor, product)`,
   indexed on both sides, returning only pairs that name the same product.
   Non-vulnerable advisory nodes and retired assets are excluded here.
2. **Python decides** — version-range comparison is Aegis's own ordering
   (§5.2) and cannot be expressed in SQL, so candidates are tested in process
   and streamed with `yield_per`.

`target_sw` is compared only when both sides state it: inventory frequently
never recorded the hosting platform, and requiring a match there would drop
real findings.

## 6. False-positive controls (§5.3)

Two are decided by the inventory, two at match time. **None of them suppress a
match** — a suppressed match is one nobody can review. They flag it, cap its
confidence, and bar auto-escalation.

| Control | Where | Effect |
| --- | --- | --- |
| Appliance-first | `core.classification` | High confidence only for internet-facing appliances/services with an orderable version |
| Backport awareness | `matching.flags` | Distro packages → `backport`, confidence forced to low |
| Config dependence | `matching.flags` | `config`, capped at medium |
| Verification gate | `matching.flags` | Every match is born `unverified` |

Config dependence has two triggers. The explicit one is
`intel_record.config_dependent`, owned by `PSIRT` — i.e. produced by the
phase-4 advisory extraction, exactly like `vendor_confirmed`. The structural
one is available today: an advisory whose configuration names products that
are *not themselves vulnerable* describes a platform combination rather than a
single affected product.

`MatchVerdict.auto_escalatable` is the single place phase 3 reads to know
whether a match may be raised without a human.

## 7. Behaviour worth knowing

* **An asset with no orderable version is matched and flagged**, not dropped
  and not silently asserted. §5.2 says such a version downgrades confidence;
  dropping it would hide a real finding, asserting it would invent one.
* **An empty discovery pass never mass-retires.** Retirement is scoped by
  source, so a scanner import cannot retire what only ASM can see.
* **Matches reopen.** A regression back to a vulnerable version reopens the
  original match rather than creating a second one.
* **Re-matching can be scoped to CVE ids**, so new intel does not force a full
  re-match of every tenant (§10 steps 3 and 6).

## 8. Not built in this phase

* **Scanner, ASM, cloud and CMDB/SBOM adapters** (§3.1). Only the generic
  normalised import (JSON/CSV) is implemented. Every adapter is a parser that
  emits `InventoryItem` objects; nothing downstream can tell the difference,
  and no store or matcher change is needed for any of them.
* **Exposure verification** (§6) — phase 3. Until it exists every match
  carries `unverified`, and `exposure_verified_at` stays null.
* **Scoring** (§7) — phase 3. The matcher records confidence and flags; it
  assigns no tier.
