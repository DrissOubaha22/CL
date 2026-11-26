# Tenancy, security and delivery — implementation notes

Reference notes for phase 5, keyed to *Aegis — Technical Specification v1.0*.

Phase 5 is done when there are "isolated tenants; delivery wired" (§14).
Isolation is asserted by `tests/integration/test_api.py::TestCrossTenant`
and `tests/integration/test_isolation.py`; delivery by
`tests/integration/test_delivery.py`.

## 1. Isolation has three layers, not one

Schema-per-tenant (phase 2) was the first. Phase 5 adds the two that stop
the attacks schema separation does not:

| Layer | Stops | Enforced by |
| --- | --- | --- |
| Schema-per-tenant | reading another tenant's rows | the schema is not in the search path |
| RBAC at the access layer | reading a tenant you hold no role in | `tenant_access` on every endpoint |
| Database roles | a tenant worker writing the shared intel | PostgreSQL grants |

The third matters because the intel tables are *deliberately* in reach — the
matcher joins against them. Only the database can make them read-only, and
`aegis db grants` emits or applies the statements that do.
`tests/integration/test_isolation.py` connects as the tenant role and
asserts the writes fail.

## 2. A role is held *in a tenant*

`Principal.tenant_roles` maps a tenant slug to the roles held there. Every
permission check takes both a permission and a tenant, and there is no
overload that omits the tenant — "read cases" without naming one is simply
false.

The platform role is disjoint from the tenant roles: `ROLE_PERMISSIONS` has
no overlap between them, and a test asserts it. A platform operator can run
the shared feeds and read the denial log, and cannot read any tenant's
assets, cases or bulletins. Running the feeds does not require anyone's
hostnames.

**A refusal is a 404, not a 403.** Confirming a tenant exists to someone
holding no role in it is itself a disclosure. A request for a real tenant
and one for an invented one return byte-identical responses, which a test
checks.

## 3. The audit log is append-only, enforced by the database

§11 asks for an "append-only log of access, matches, verifications, bulletin
issuance". A migration installs a trigger that raises on UPDATE and DELETE.
A log the application merely promises not to rewrite is a log that anyone
with application access can rewrite.

It lives in the **control** schema rather than per tenant, because the event
most worth recording — a denied cross-tenant read — cannot be written into a
schema the principal has no access to. The cost is that a tenant's own trail
is a filtered view; `tenant_slug` is indexed for it.

**Each event is committed as it is written.** An earlier version only
flushed, and the denial was rolled back by the very `AccessDenied` it was
recording — the exception propagated out of the surrounding transaction and
took the audit row with it. The trail therefore holds a session of its own.
An audit event is an independent fact about something that already happened;
it does not belong to the caller's transaction.

An audit write that fails is logged loudly and does not break the audited
work: losing a bulletin because the audit table was full would be the worse
failure.

## 4. SSO: unconfigured means closed

`TokenVerifier` rejects every token when no issuer is configured, and
`create_app` refuses to start in that state. A verifier that falls open when
misconfigured is worse than no verifier, because it looks like one — and an
operator should learn about it at startup rather than from user reports.

Signatures are checked against the provider's JWKS; issuer, audience and
expiry are all verified, with configurable clock-skew leeway. Roles come
from a claim mapping tenant slug to role names, and **an unknown role name
is dropped**: an identity provider that invents a role should grant nothing,
not something.

## 5. Secrets name a vault, they are not a vault

`SecretStore` is the seam. Two backends ship — the process environment (what
an orchestrator injects a vault-held secret as) and a directory of files
(what a mounted Kubernetes secret or a Vault agent sidecar looks like). A
direct HashiCorp Vault or Secrets Manager client implements the same
protocol and nothing else changes.

Rotation is **observable rather than automatic**: `describe()` reports a
secret's age and flags it stale past the configured window. Rotating on a
schedule is the orchestrator's job; noticing that nobody did is this
system's. A backend that cannot date a secret reports an unknown age, and an
unknown age is never reported stale — flagging everything trains people to
ignore the report.

A webhook URL is a bearer credential, so `delivery_destination` stores the
*name* of the secret holding it and never the value.

## 6. Delivery (§12)

Only **issued** bulletins are sent — auto-issued under §8.2, or released by
an analyst. A queued bulletin is a draft awaiting a human, and pushing
drafts into an on-call channel is how an alerting integration gets muted.

Delivery is idempotent through a partial unique index on successful rows,
not through the sender remembering: one success per (bulletin, destination).
Failures leave a row each time and are retried on the next run, because "the
webhook was down for an hour" is a question someone will ask.

A **missing secret is not retried**. Retrying will not conjure a vault
entry, so it is counted separately as a misconfiguration and surfaced.

Slack and Teams read different JSON; both formatters carry a plain-text
summary so a client that renders neither still gets something readable.

## 7. The API (§12)

Every tenant endpoint takes its tenant from the path and its authorisation
from a `tenant_access` dependency, which authenticates, checks the
permission against that tenant, and writes the access to the audit log
before any handler body runs. There is no dependency yielding an unscoped
session, so an endpoint cannot read across tenants by forgetting a filter —
it would have to construct its own session, which review catches.

Response models are explicit rather than serialised ORM rows. A row
serialised wholesale leaks whatever column is added to it next.

`create_app` takes an optional engine. A deployment serving a read replica
to the portal uses it; so do the tests, which would otherwise open sessions
on the configured DSN.

## 8. Not built

* **A web dashboard** (§13). The API is what a dashboard would consume, and
  its OpenAPI schema is generated.
* **Jira / ServiceNow / email** (§12). The delivery seam is
  `format_payload` plus a `DeliveryChannel` value; a ticketing integration
  adds a channel and a formatter, and the tier → priority mapping is the
  `Tier` rank.
* **Encryption at rest and in transit** (§11) is deployment configuration —
  TLS on the database connection, an encrypted volume. `require_database_tls`
  exists as the switch to assert it; the enforcement belongs with the
  connection string, not in application code that could be bypassed.
* **Automatic secret rotation.** Age is reported; rotating is the
  orchestrator's job.
