# Verification and scoring — implementation notes

Reference notes for phase 3, keyed to *Aegis — Technical Specification v1.0*.

Phase 3 is done when "verified, tiered cases; false positives cut" (§14).
`tests/integration/test_scoring.py::TestFullCycle` is that criterion: four
hosts running the same vulnerable version, four different live realities, and
two of the four findings removed.

## 1. Verification is bounded by construction, not by discipline

§6.2 draws the boundary: "limited to the specific host and service named by a
candidate match", "not broad network scanning", "performs no exploitation".
`aegis/verification/scope.py` is where that is enforced, so no call site can
widen it:

* A `ProbeTarget` is one host and one port. No API in the package accepts a
  range, a CIDR, a port list or a URL — each is rejected with a specific
  error, before any resolution.
* Address space is checked with `ipaddress.is_global`, which is exactly the
  question §6.1 asks. That covers more than an enumeration would: RFC1918,
  loopback, link-local, multicast, TEST-NET and benchmarking ranges are all
  refused by default.
* A *name* is checked after resolution, because what matters is where the
  packets would actually go, not what the name looks like.
* Nothing in the package constructs a payload. The probes connect, complete a
  TLS handshake, and issue one request for `/`.
* Probes to the same host are spaced, so verifying twenty matches on one
  appliance does not look like a scan.

`verification_allow_private_targets` opts into private space for a deployment
verifying an internal footprint. It is threaded through both the shape check
and the resolution check; an earlier version checked literal addresses
without honouring it, which silently made private targets unprobeable even
when enabled.

Restricting targets to the client's *authorised* footprint is an onboarding
control rather than a code one: discovery (§3.1) runs over domains and ranges
the client declared, and the inventory that results is what names these hosts.

## 2. Six outcomes, because "we could not look" is not "nothing is there"

| Outcome | Means | Effect |
| --- | --- | --- |
| `confirmed` | answered, not fronted, version not contradicted | clears the gate |
| `fronted` | a WAF or proxy answered, not the origin | clears the gate, caps below Critical |
| `version_mismatch` | live version is outside the affected range | match resolved |
| `unreachable` | nothing answered | stays unverified |
| `inconclusive` | the check could not run | **changes nothing** |
| `not_applicable` | internal or client-side asset (§6.3) | not probed |

`inconclusive` exists because of §6.2's rule that "checks that cannot confirm
reachability leave the match at its pre-verification (lower) tier rather than
escalating on assumption". Collapsing it into `unreachable` would let a DNS
failure masquerade as evidence that a host is safe.

Version confirmation is the check that cuts false positives. A match resting
on a scanner's stale record dies here: inventory says FortiOS 7.4.1, the live
banner says 7.4.9, the advisory covers `< 7.4.3`, so the finding is resolved.
A banner naming a *different product* proves nothing either way — that is a
proxy or another service answering, and it is recorded as such rather than
treated as a mismatch.

## 3. Tiering is two steps, kept apart

```
base_tier(inputs)   →  "how bad would this be if the match is real?"   (§7.2)
apply_gates(...)    →  "how far has that been established?"       (§5.3, §6)
```

`base_tier` is the specification's pseudocode transcribed in its own order.
`apply_gates` applies the caps. Both the capped and uncapped tiers are stored
(`tier`, `tier_before_gate`), with every input and every cap reason in
`factors`.

That separation is what lets a case explain itself. `aegis case show` prints
"tier=MEDIUM (before gate: critical) … cap: capped at medium by: unverified".
Collapsing the two would produce a tier nobody can argue with, which in
practice means a tier nobody acts on.

### The caps

| Cap | Source | Effect |
| --- | --- | --- |
| `unverified` | §5.3 verification gate | at most Medium |
| `backport` | §5.3 backport awareness | at most Medium |
| `config` | §5.3 configuration dependence | at most Medium |
| `unparseable_version` | §5.2 | at most Medium |
| WAF fronting | §6.1 | Critical → High |

`unbounded_range` deliberately does **not** cap: it is a precision caveat
about the advisory, not a doubt about the match.

### Two rules from §7.2's prose

*"Vendor-confirmed exploitation forces High/Critical before CISA KEV lists
it."* `ScoreInputs.exploited` is true on `vendor_confirmed` alone, so a PSIRT
advisory reaches Critical with no KEV entry. The producer of that field is
phase 4; the consumer is in place and tested.

*"EPSS raises but never lowers a tier derived from confirmed exploitation."*
EPSS appears in exactly one place — the `MEDIUM` branch of `base_tier` — and
nowhere in `apply_gates`. It can lift an unexploited CVE to Medium and can do
nothing else. There is a test for every low EPSS value against a Critical
input.

## 4. Where each input comes from

§7.1 lists six inputs. They live in three places, and scoring is the only
thing that reads all three:

* `intel_record` (shared): `exploit_status`, `on_kev`, `vendor_confirmed`,
  `public_exploit`, `ransomware`, `epss`
* `asset` (tenant): `exposure_class`, `criticality`, `exposure_verified_at`
* `match` + `verification` (tenant): `flags`, `waf_detected`

A match whose CVE has no intel record is **skipped**, not scored on defaults:
every §7.1 input comes from that record, so scoring without it would invent a
tier. The count is reported as `skipped_no_intel`.

## 5. Behaviour worth knowing

* **Scoring touches no network.** Verification decides what is real; scoring
  reads that conclusion. The two are separate steps in §10 and separate
  modules here.
* **Verification has a freshness window** (`verification_ttl_hours`, 24 by
  default). A fresh check costs a packet; a stale tier costs a wrong
  decision, so re-verification is cheap and automatic.
* **Every check is logged**, including the ones that concluded nothing, so an
  escalation can be explained from the evidence that drove it (§6.2).
* **Verification can be turned off entirely.** A deployment that must not
  emit traffic sets `verification_enabled=false`; nothing is probed, nothing
  is claimed, and every match keeps its unverified tier.
* **Due dates come from the tier** (§7.2's table). Critical carries none: it
  is out-of-band, not scheduled.

## 6. Not built in this phase

* **Bulletin generation and routing** (§8) — phase 4. `Score.auto_escalatable`
  is the single predicate §8.2's automation tiers will read.
* **`vendor_confirmed` and `config_dependent` producers** (§4.2) — phase 4.
  Both fields, their ownership and every consumer are in place.
* **Ticketing, alerting, portal** (§12) — phase 5.
