# Intel core — implementation notes

Reference notes for phase 1, keyed to the technical specification. Section
numbers (§) refer to *Aegis — Technical Specification v1.0*.

## 1. Where the spec left a choice, and what was chosen

### Contributions as the source of truth (§9)

The spec names `intel_record` and `intel_source`. Writing feed output straight
onto `intel_record` would make a record the accumulated history of every write
it ever received, which breaks in two ways:

* A re-run that saw different data would leave fields from the earlier run
  standing next to fields from the later one.
* A retraction has nowhere to go. CISA does remove entries from KEV. With
  `on_kev` written directly, the only way back is a targeted "unset" that has
  to know which source set it.

So each source's output lands in `intel_contribution` (one row per CVE per
source, holding only the fields that source owns) and `intel_record` is
re-derived from them. Re-running is idempotent by construction, and
`retract_source` removes a source's rows and re-derives.

Cost: a write is two steps instead of one, and the record is strictly a cache
of the contributions. That is the right trade for a store several later phases
read from.

### `affected_cpe` as its own table (§9 vs §5)

§9 lists `affected_cpes[]` as a field on `intel_record`. It is a separate
table here because §5.1 joins tenant inventory against it per asset: a JSON
array would force a per-row scan, while the table is indexed on
`(vendor, product)` with the version bounds stored unflattened. The data is
identical; only the access path changes.

### `feed_run` (not in the spec)

§11 requires an append-only audit log, and §4.1 describes scheduled jobs. A
run journal serves both, and carries the incremental watermark for NVD. A
failed run is journalled too, so a feed that has been silently failing for a
week is visible in `aegis intel status` rather than inferred from absence.

## 2. Exploitation status (§7.1, §7.2)

```
active := on_kev OR vendor_confirmed OR exploited_in_wild
poc    := public_exploit            (exploit code exists; no in-the-wild use)
none   := neither
```

§7.2's comment reads `exploited := on_kev or vendor_confirmed`, and its prose
adds that "vendor-confirmed exploitation forces High/Critical before CISA KEV
lists it". `exploited_in_wild` is the third term, carrying VulnCheck's
independent assertion (§7.1 names VulnCheck as a source of exploit status).

`vendor_confirmed` has no producer in phase 1. It is owned by `PSIRT`, which
is the phase-4 LLM extraction path (§4.2). The field, the ownership entry and
the derivation are in place, so phase 4 adds a pipeline and nothing else.

EPSS deliberately feeds neither branch. §7.2: "EPSS raises but never lowers a
tier derived from confirmed exploitation" — that is a scoring rule for phase
3, and keeping EPSS out of the status derivation is what leaves it available
as an independent input there.

## 3. Version comparison (§5.2)

Three rules, applied to each alphabetic token in order:

1. Glued to a digit — `7.4.2b` — is a vendor patch letter and sorts **above**
   the bare release.
2. A known marker word sorts by meaning whatever the separator:
   `alpha/beta/rc/pre/dev/snapshot/...` below, `build/patch/sp/hotfix/rev/...`
   above. So `10.0.1_build1234 > 10.0.1` but `2.0.0-beta < 2.0.0`.
3. Anything else: a hyphen introduces a pre-release (semver), any other
   separator a post-release.

Numeric tokens compare numerically, so `7.4.10 > 7.4.9`. Trailing zeros are
padding, so `1.2 == 1.2.0`.

Wildcards (`*`, `-`, `n/a`, empty) and digit-free strings (`latest`) raise
`UnparseableVersion`. §5.2 requires that a missing or unparseable version
*downgrade confidence* rather than assert a match, which a caller can only do
if the comparison refuses rather than guesses.

Rule 3 is the one judgement call: vendors are inconsistent, and an unknown
dotted suffix could mean either. The marker word lists cover the cases seen in
practice; extend them rather than changing the fallback.

## 4. False-positive groundwork (§5.3)

Phase 1 preserves what the flags in §5.3 will need:

* `affected_cpe.vulnerable` keeps NVD's flag, so a node present only as
  platform context is distinguishable from an affected product.
* `part` distinguishes `a`/`o`/`h`, which is how appliance-first matching
  (§3.3) separates an appliance OS from an application package.
* `target_sw` is stored when stated and compared only when both sides state
  it, so advisory intel naming a platform still matches inventory that never
  recorded one.

Backport awareness and configuration dependence (§5.3) are match-time flags
and belong to phase 2; nothing here forecloses them.

## 5. Feed behaviour

| Feed | Mode | Notes |
| --- | --- | --- |
| CISA KEV | full poll + diff | Catalogue is complete, so absence is delisting. An **empty** fetch is treated as a broken feed and never mass-retracts. |
| NVD | incremental | `lastModStartDate`/`lastModEndDate`, windows capped at 120 days as the API requires, paginated by `startIndex`. Watermark advances only on success. |
| FIRST EPSS | batch by CVE | Scores the CVEs already in the store; it annotates, it never introduces a CVE. |

Unchanged data is detected by a content digest over the asserted facts,
excluding `retrieved_at` — so a poll that sees no change costs one HTTP
request and no writes, while staleness remains visible because the retrieval
timestamp is still refreshed.

## 6. Not built, deliberately

* **VulnCheck KEV** (§4.1) — commercial, licensed. `FeedSource.VULNCHECK_KEV`,
  its field ownership and the `exploited_in_wild` term exist; the pipeline
  needs a token and a response shape to normalise.
* **Exploit-DB / Metasploit / Nuclei** (§4.1) — git mirrors indexed by CVE.
  Ownership of `public_exploit` is already assigned to them.
* **LLM extraction** (§4.2) — phase 4. `FeedSource.PSIRT` is reserved so the
  provenance tables take its output without a migration, and `SourceRef`
  already carries the per-field `url` + `quote` that §4.2 requires.

Each is a new `FeedPipeline` subclass plus a registry entry. No change to the
store, the derivation or the schema is needed for any of them.
