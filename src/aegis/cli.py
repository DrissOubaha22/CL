"""``aegis`` command line - operating the intel core."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Annotated

import structlog
import typer
from sqlalchemy import desc, func, select

from aegis.auth.audit import audit_trail
from aegis.auth.secrets import build_secret_store
from aegis.bulletins.runner import generate_all_tenants, generate_for_tenant
from aegis.config import get_settings
from aegis.core.enums import (
    AuditOutcome,
    AutomationPolicy,
    BulletinStatus,
    DeliveryChannel,
    ExploitStatus,
    FeedSource,
    RunStatus,
    Tier,
)
from aegis.db.base import get_engine, session_scope
from aegis.db.grants import apply_grants, grant_statements
from aegis.db.models import (
    AffectedCpe,
    Asset,
    Bulletin,
    DeliveryDestination,
    FeedRun,
    IntelRecord,
    IntelSource,
    Match,
    MatchRun,
    Score,
    Verification,
)
from aegis.db.ordering import confidence_order, tier_order
from aegis.db.tenancy import (
    active_tenants,
    create_tenant,
    get_tenant,
    session_for_control,
    tenant_session_scope,
)
from aegis.db.tenant_migrations import head_revision, tenant_revision, upgrade_all_tenants
from aegis.delivery.runner import deliver_all_tenants, deliver_for_tenant
from aegis.intel.runner import run_pipeline, run_pipelines
from aegis.inventory.loader import load_inventory_file
from aegis.inventory.schemas import InventorySource
from aegis.inventory.store import import_inventory
from aegis.logging import configure_logging
from aegis.matching.runner import match_all_tenants, match_tenant
from aegis.scoring.runner import assess_all_tenants, assess_tenant

log = structlog.get_logger(__name__)

app = typer.Typer(
    help="Aegis intel core - deterministic feed ETL over the shared intel store.",
    no_args_is_help=True,
    add_completion=False,
)
intel_app = typer.Typer(help="Shared intel store operations.", no_args_is_help=True)
app.add_typer(intel_app, name="intel")

tenant_app = typer.Typer(help="Tenant registry and schemas.", no_args_is_help=True)
app.add_typer(tenant_app, name="tenant")

inventory_app = typer.Typer(help="Per-tenant inventory.", no_args_is_help=True)
app.add_typer(inventory_app, name="inventory")

match_app = typer.Typer(help="Matching engine.", no_args_is_help=True)
app.add_typer(match_app, name="match")

case_app = typer.Typer(help="Verified, tiered cases.", no_args_is_help=True)
app.add_typer(case_app, name="case")

bulletin_app = typer.Typer(help="Client-facing advisories.", no_args_is_help=True)
app.add_typer(bulletin_app, name="bulletin")

delivery_app = typer.Typer(help="Where bulletins are sent.", no_args_is_help=True)
app.add_typer(delivery_app, name="delivery")

audit_app = typer.Typer(help="The audit trail.", no_args_is_help=True)
app.add_typer(audit_app, name="audit")

db_app = typer.Typer(help="Database roles and grants.", no_args_is_help=True)
app.add_typer(db_app, name="db")


@app.callback()
def _main() -> None:
    configure_logging()


@intel_app.command("sync")
def intel_sync(
    source: Annotated[
        FeedSource | None,
        typer.Option(help="Run a single feed instead of all of them."),
    ] = None,
    stop_on_error: Annotated[
        bool, typer.Option(help="Abort remaining feeds after the first failure.")
    ] = False,
) -> None:
    """Run the deterministic feed pipelines."""
    outcomes = (
        [run_pipeline(source)] if source is not None else run_pipelines(stop_on_error=stop_on_error)
    )

    failures = 0
    for outcome in outcomes:
        marker = "ok " if outcome.ok else "FAIL"
        typer.echo(
            f"{marker} {outcome.source:<14} "
            f"seen={outcome.seen:<7} changed={outcome.changed:<7} "
            f"rejected={outcome.rejected:<5} {outcome.duration_seconds:.1f}s"
            + (f"  {outcome.error}" if outcome.error else "")
        )
        failures += 0 if outcome.ok else 1

    if failures:
        raise typer.Exit(code=1)


@intel_app.command("show")
def intel_show(
    cve_id: Annotated[str, typer.Argument(help="e.g. CVE-2026-104286")],
) -> None:
    """Print the merged intel record for one CVE, with its provenance."""
    normalised = cve_id.strip().upper()
    with session_scope() as session:
        record = session.get(IntelRecord, normalised)
        if record is None:
            typer.echo(f"{normalised}: not in the intel store")
            raise typer.Exit(code=1)

        typer.echo(f"{record.cve_id}  [{record.exploit_status}]")
        typer.echo(
            f"  kev={record.on_kev} vendor_confirmed={record.vendor_confirmed} "
            f"public_exploit={record.public_exploit} ransomware={record.ransomware}"
        )
        typer.echo(
            f"  cvss={record.cvss} epss={record.epss} "
            f"patch_available={record.patch_available} due={record.kev_due}"
        )
        if record.cwe:
            typer.echo(f"  cwe={', '.join(record.cwe)}")
        typer.echo(f"  as_of={record.as_of:%Y-%m-%d %H:%M:%SZ}")

        cpes = session.scalars(
            select(AffectedCpe)
            .where(AffectedCpe.cve_id == normalised)
            .order_by(AffectedCpe.vendor, AffectedCpe.product)
            .limit(20)
        ).all()
        if cpes:
            typer.echo("  affected:")
            for cpe in cpes:
                typer.echo(f"    {cpe.vendor}:{cpe.product} {_render_range(cpe)}")

        sources = session.scalars(
            select(IntelSource).where(IntelSource.cve_id == normalised).limit(10)
        ).all()
        if sources:
            typer.echo("  sources:")
            for item in sources:
                typer.echo(f"    [{item.source}] {item.url}")


@intel_app.command("status")
def intel_status() -> None:
    """Summarise the store and the last run of each feed."""
    with session_scope() as session:
        total = session.scalar(select(func.count()).select_from(IntelRecord)) or 0
        typer.echo(f"intel records: {total}")

        for status in ExploitStatus:
            count = (
                session.scalar(
                    select(func.count())
                    .select_from(IntelRecord)
                    .where(IntelRecord.exploit_status == status)
                )
                or 0
            )
            typer.echo(f"  {status:<7} {count}")

        typer.echo("last run per feed:")
        for source in FeedSource:
            run = session.scalars(
                select(FeedRun)
                .where(FeedRun.source == source)
                .order_by(desc(FeedRun.started_at))
                .limit(1)
            ).first()
            if run is None:
                continue
            marker = "ok " if run.status is RunStatus.SUCCESS else run.status
            typer.echo(
                f"  {source:<14} {marker:<8} {run.started_at:%Y-%m-%d %H:%M}Z "
                f"seen={run.records_seen} changed={run.records_changed}"
                + (f"  {run.error}" if run.error else "")
            )


@app.command("config")
def show_config() -> None:
    """Print the effective configuration, with secrets masked."""
    settings = get_settings()
    for name, value in settings.model_dump().items():
        typer.echo(f"{name} = {_present(name, value)}")


# --------------------------------------------------------------------------
# tenant
# --------------------------------------------------------------------------


@tenant_app.command("create")
def tenant_create(
    slug: Annotated[str, typer.Argument(help="Lower-case identifier, e.g. acme")],
    name: Annotated[str, typer.Option(help="Display name.")],
    automation_policy: Annotated[
        AutomationPolicy, typer.Option(help="Bulletin automation tier (spec §8.2).")
    ] = AutomationPolicy.REVIEW_ALL,
    region: Annotated[str | None, typer.Option(help="Data region.")] = None,
) -> None:
    """Register a tenant and provision its isolated schema."""
    with session_for_control() as session:
        tenant = create_tenant(
            session,
            slug=slug,
            name=name,
            automation_policy=automation_policy,
            region=region,
        )
        typer.echo(f"created {tenant.slug} -> schema {tenant.schema_name}")


@tenant_app.command("list")
def tenant_list() -> None:
    """List tenants and how far each schema has been migrated."""
    head = head_revision()
    with session_for_control() as session:
        tenants = active_tenants(session)
        if not tenants:
            typer.echo("no tenants registered")
            return
        typer.echo(f"head revision: {head}")
        for tenant in tenants:
            current = tenant_revision(tenant)
            marker = "ok " if current == head else "STALE"
            typer.echo(
                f"  {marker} {tenant.slug:<16} {tenant.schema_name:<24} "
                f"{tenant.automation_policy:<20} rev={current}"
            )


@tenant_app.command("upgrade")
def tenant_upgrade(
    slug: Annotated[str | None, typer.Option(help="Upgrade one tenant instead of all.")] = None,
) -> None:
    """Apply the per-tenant migrations to each tenant schema."""
    with session_for_control() as session:
        tenants = [get_tenant(session, slug)] if slug else active_tenants(session)
        for state in upgrade_all_tenants(tenants):
            marker = "ok " if state.up_to_date else "STALE"
            typer.echo(f"{marker} {state.slug:<16} rev={state.current}")


# --------------------------------------------------------------------------
# inventory
# --------------------------------------------------------------------------


@inventory_app.command("import")
def inventory_import(
    slug: Annotated[str, typer.Argument(help="Tenant slug.")],
    path: Annotated[str, typer.Argument(help="A .json, .csv or .tsv file.")],
    source: Annotated[
        InventorySource | None,
        typer.Option(help="Override the source recorded on every item."),
    ] = None,
) -> None:
    """Import discovered products into a tenant's inventory."""
    batch = load_inventory_file(path, source=source)
    with tenant_session_scope(slug) as session:
        result = import_inventory(session, batch)

    typer.echo(
        f"seen={result.seen} created={result.created} "
        f"updated={result.updated} rejected={result.rejected}"
    )
    for what, reason in result.rejections[:10]:
        typer.echo(f"  rejected {what}: {reason}")
    if result.rejected:
        raise typer.Exit(code=1)


@inventory_app.command("list")
def inventory_list(
    slug: Annotated[str, typer.Argument(help="Tenant slug.")],
    limit: Annotated[int, typer.Option(help="Maximum rows to print.")] = 50,
) -> None:
    """List a tenant's active inventory."""
    with tenant_session_scope(slug) as session:
        assets = session.scalars(
            select(Asset)
            .where(Asset.retired_at.is_(None))
            .order_by(Asset.hostname, Asset.product_name)
            .limit(limit)
        ).all()
        if not assets:
            typer.echo("inventory is empty")
            return
        for asset in assets:
            typer.echo(
                f"  {asset.hostname:<24} {asset.product_name:<18} "
                f"{asset.version or '-':<12} {asset.exposure_class:<12} "
                f"{asset.product_class:<16} conf={asset.match_confidence}"
            )


# --------------------------------------------------------------------------
# match
# --------------------------------------------------------------------------


@match_app.command("run")
def match_run(
    slug: Annotated[str | None, typer.Option(help="Match one tenant instead of all.")] = None,
    cve: Annotated[list[str] | None, typer.Option(help="Restrict to these CVE ids.")] = None,
) -> None:
    """Match tenant inventory against the shared intel store."""
    cve_ids = [item.strip().upper() for item in cve] if cve else None
    results = (
        [match_tenant(slug, cve_ids=cve_ids)] if slug else list(match_all_tenants(cve_ids=cve_ids))
    )

    failures = 0
    for result in results:
        outcome = result.outcome
        marker = "ok " if result.ok else "FAIL"
        typer.echo(
            f"{marker} {result.slug:<16} assets={outcome.assets_considered:<6} "
            f"candidates={outcome.candidates_tested:<7} open={outcome.matches_open:<6} "
            f"new={outcome.matches_new:<5} resolved={outcome.matches_resolved}"
            + (f"  {outcome.error}" if outcome.error else "")
        )
        failures += 0 if result.ok else 1

    if failures:
        raise typer.Exit(code=1)


@match_app.command("list")
def match_list(
    slug: Annotated[str, typer.Argument(help="Tenant slug.")],
    open_only: Annotated[bool, typer.Option(help="Hide resolved matches.")] = True,
    limit: Annotated[int, typer.Option(help="Maximum rows to print.")] = 50,
) -> None:
    """List a tenant's matches, highest confidence first."""
    with tenant_session_scope(slug) as session:
        statement = select(Match).order_by(confidence_order(Match.confidence).desc(), Match.cve_id)
        if open_only:
            statement = statement.where(Match.resolved_at.is_(None))
        matches = session.scalars(statement.limit(limit)).all()

        if not matches:
            typer.echo("no matches")
            return
        for match in matches:
            asset = match.asset
            flags = ",".join(match.flags) or "-"
            typer.echo(
                f"  {match.cve_id:<18} {asset.hostname:<24} "
                f"{asset.product_name}/{asset.version or '-':<12} "
                f"conf={match.confidence:<7} {match.matched_range or '':<22} [{flags}]"
            )


@match_app.command("status")
def match_status(
    slug: Annotated[str, typer.Argument(help="Tenant slug.")],
) -> None:
    """Summarise a tenant's matches and last matching pass."""
    with tenant_session_scope(slug) as session:
        total = (
            session.scalar(
                select(func.count()).select_from(Match).where(Match.resolved_at.is_(None))
            )
            or 0
        )
        typer.echo(f"open matches: {total}")
        for confidence in ("high", "medium", "low"):
            count = (
                session.scalar(
                    select(func.count())
                    .select_from(Match)
                    .where(Match.resolved_at.is_(None), Match.confidence == confidence)
                )
                or 0
            )
            typer.echo(f"  {confidence:<7} {count}")

        run = session.scalars(select(MatchRun).order_by(desc(MatchRun.started_at)).limit(1)).first()
        if run is not None:
            typer.echo(
                f"last run: {run.status} at {run.started_at:%Y-%m-%d %H:%M}Z "
                f"assets={run.assets_considered} new={run.matches_new} "
                f"resolved={run.matches_resolved}"
            )


# --------------------------------------------------------------------------
# case: verify + score
# --------------------------------------------------------------------------


@case_app.command("assess")
def case_assess(
    slug: Annotated[str | None, typer.Option(help="Assess one tenant instead of all.")] = None,
    verify: Annotated[
        bool,
        typer.Option(help="Run exposure verification before scoring (spec §6)."),
    ] = True,
    force: Annotated[
        bool, typer.Option(help="Re-verify matches already checked recently.")
    ] = False,
) -> None:
    """Verify exposure, then score each open match into a tier."""
    results = (
        [assess_tenant(slug, verify=verify, force=force)]
        if slug
        else list(assess_all_tenants(verify=verify, force=force))
    )

    failures = 0
    for result in results:
        marker = "ok " if result.ok else "FAIL"
        check = result.verification
        score = result.scoring
        typer.echo(
            f"{marker} {result.slug:<16} "
            f"probed={check.probed:<5} confirmed={check.confirmed:<5} "
            f"cut={check.false_positives_cut:<5} "
            f"scored={score.scored:<5} retiered={score.tier_changed}"
            + (f"  {score.error}" if score.error else "")
        )
        if score.by_tier:
            ordered = sorted(
                score.by_tier.items(),
                key=lambda item: -Tier(item[0]).rank,
            )
            typer.echo("     " + "  ".join(f"{tier}={count}" for tier, count in ordered))
        failures += 0 if result.ok else 1

    if failures:
        raise typer.Exit(code=1)


@case_app.command("list")
def case_list(
    slug: Annotated[str, typer.Argument(help="Tenant slug.")],
    tier: Annotated[Tier | None, typer.Option(help="Show only this tier.")] = None,
    auto_only: Annotated[
        bool, typer.Option(help="Only cases that may be escalated automatically.")
    ] = False,
    limit: Annotated[int, typer.Option(help="Maximum rows to print.")] = 50,
) -> None:
    """List a tenant's scored cases, most severe first."""
    with tenant_session_scope(slug) as session:
        statement = (
            select(Score)
            .join(Match, Match.match_id == Score.match_id)
            .where(Match.resolved_at.is_(None))
            .order_by(tier_order(Score.tier).desc(), Score.due_at)
        )
        if tier is not None:
            statement = statement.where(Score.tier == tier)
        if auto_only:
            statement = statement.where(Score.auto_escalatable.is_(True))

        scores = session.scalars(statement.limit(limit)).all()
        if not scores:
            typer.echo("no scored cases")
            return

        for score in scores:
            match = score.match
            asset = match.asset
            capped = (
                f" (would be {score.tier_before_gate})"
                if score.tier_before_gate is not score.tier
                else ""
            )
            due = f"{score.due_at:%Y-%m-%d}" if score.due_at else "out-of-band"
            typer.echo(
                f"  {str(score.tier).upper():<9} {match.cve_id:<18} "
                f"{asset.hostname:<24} {asset.product_name}/{asset.version or '-'}"
            )
            typer.echo(
                f"            due={due:<12} auto={score.auto_escalatable} "
                f"exposure={asset.exposure_class}{capped}"
            )
            reasons = score.factors.get("cap_reasons") or []
            for reason in reasons:
                typer.echo(f"            - {reason}")


@case_app.command("show")
def case_show(
    slug: Annotated[str, typer.Argument(help="Tenant slug.")],
    match_id: Annotated[int, typer.Argument(help="Match id.")],
) -> None:
    """Explain one case: its tier, its inputs, and every check behind it."""
    with tenant_session_scope(slug) as session:
        match = session.get(Match, match_id)
        if match is None:
            typer.echo(f"no match {match_id} for tenant {slug}")
            raise typer.Exit(code=1)

        asset = match.asset
        typer.echo(f"{match.cve_id} on {asset.hostname}")
        typer.echo(
            f"  {asset.product_name}/{asset.version or '-'} "
            f"exposure={asset.exposure_class} criticality={asset.criticality}"
        )
        typer.echo(f"  match confidence={match.confidence} flags={','.join(match.flags) or '-'}")

        score = match.score
        if score is None:
            typer.echo("  not scored yet")
        else:
            typer.echo(
                f"  tier={str(score.tier).upper()} "
                f"(before gate: {score.tier_before_gate}) "
                f"auto_escalatable={score.auto_escalatable}"
            )
            typer.echo(f"  window={score.tier.remediation_window} due={score.due_at}")
            for key in (
                "exploited",
                "on_kev",
                "vendor_confirmed",
                "public_exploit",
                "ransomware",
                "epss",
                "waf_detected",
            ):
                typer.echo(f"    {key} = {score.factors.get(key)}")
            for reason in score.factors.get("cap_reasons") or []:
                typer.echo(f"    cap: {reason}")

        checks = session.scalars(
            select(Verification)
            .where(Verification.match_id == match_id)
            .order_by(desc(Verification.checked_at))
            .limit(5)
        ).all()
        if checks:
            typer.echo("  verification history:")
            for check in checks:
                typer.echo(
                    f"    {check.checked_at:%Y-%m-%d %H:%M}Z {check.outcome:<16} "
                    f"reachable={check.reachable} waf={check.waf_detected} "
                    f"banner={check.observed_banner or '-'}"
                )


# --------------------------------------------------------------------------
# bulletin
# --------------------------------------------------------------------------


@bulletin_app.command("generate")
def bulletin_generate(
    slug: Annotated[str | None, typer.Option(help="One tenant instead of all.")] = None,
    regenerate: Annotated[
        bool, typer.Option(help="Redraft matches that already have a bulletin.")
    ] = False,
) -> None:
    """Draft a bulletin per scored match and route it (spec §8)."""
    results = (
        [generate_for_tenant(slug, regenerate=regenerate)]
        if slug
        else list(generate_all_tenants(regenerate=regenerate))
    )

    failures = 0
    for item in results:
        outcome = item.result
        marker = "ok " if item.ok else "FAIL"
        typer.echo(
            f"{marker} {item.slug:<16} considered={outcome.considered:<5} "
            f"created={outcome.created:<5} auto_issued={outcome.auto_issued:<5} "
            f"queued={outcome.queued:<5} skipped={outcome.skipped_existing}"
            + (f"  {outcome.error}" if outcome.error else "")
        )
        if outcome.created:
            typer.echo(
                f"     drafts: model={outcome.drafts_from_model} "
                f"deterministic={outcome.drafts_fallback}"
            )
        failures += 0 if item.ok else 1

    if failures:
        raise typer.Exit(code=1)


@bulletin_app.command("list")
def bulletin_list(
    slug: Annotated[str, typer.Argument(help="Tenant slug.")],
    status: Annotated[BulletinStatus | None, typer.Option(help="Show only this status.")] = None,
    limit: Annotated[int, typer.Option(help="Maximum rows to print.")] = 50,
) -> None:
    """List a tenant's bulletins, most severe first."""
    with tenant_session_scope(slug) as session:
        statement = select(Bulletin).order_by(tier_order(Bulletin.tier).desc(), Bulletin.cve_id)
        if status is not None:
            statement = statement.where(Bulletin.status == status)

        bulletins = session.scalars(statement.limit(limit)).all()
        if not bulletins:
            typer.echo("no bulletins")
            return

        for bulletin in bulletins:
            asset = bulletin.match.asset
            typer.echo(
                f"  #{bulletin.bulletin_id:<4} {str(bulletin.tier).upper():<9} "
                f"{bulletin.cve_id:<18} {asset.hostname:<24} "
                f"{bulletin.status}"
            )
            if bulletin.review_reasons:
                typer.echo(f"        review: {', '.join(bulletin.review_reasons)}")


@bulletin_app.command("show")
def bulletin_show(
    slug: Annotated[str, typer.Argument(help="Tenant slug.")],
    bulletin_id: Annotated[int, typer.Argument(help="Bulletin id.")],
    draft_only: Annotated[
        bool,
        typer.Option(help="Show only the public draft - what the model wrote."),
    ] = False,
) -> None:
    """Print a bulletin as the client receives it."""
    with tenant_session_scope(slug) as session:
        bulletin = session.get(Bulletin, bulletin_id)
        if bulletin is None:
            typer.echo(f"no bulletin {bulletin_id} for tenant {slug}")
            raise typer.Exit(code=1)

        if draft_only:
            typer.echo(
                f"-- public draft, written by {bulletin.drafted_by or 'Aegis (no model)'} --"
            )
            typer.echo(bulletin.draft_body or "(none)")
            return

        typer.echo(bulletin.body)
        typer.echo("")
        typer.echo(
            f"-- status={bulletin.status} auto_issued={bulletin.auto_issued} "
            f"drafted_by={bulletin.drafted_by or 'Aegis (no model)'}"
        )
        if bulletin.review_reasons:
            typer.echo(f"-- review: {bulletin.detail.get('routing', '')}")


@bulletin_app.command("issue")
def bulletin_issue(
    slug: Annotated[str, typer.Argument(help="Tenant slug.")],
    bulletin_id: Annotated[int, typer.Argument(help="Bulletin id.")],
    analyst: Annotated[str, typer.Option(help="Who reviewed it.")],
    reject: Annotated[bool, typer.Option(help="Reject instead of issuing.")] = False,
) -> None:
    """Record an analyst's decision on a queued bulletin (spec §8.2)."""
    with tenant_session_scope(slug) as session:
        bulletin = session.get(Bulletin, bulletin_id)
        if bulletin is None:
            typer.echo(f"no bulletin {bulletin_id} for tenant {slug}")
            raise typer.Exit(code=1)
        if not bulletin.awaits_review:
            typer.echo(f"bulletin {bulletin_id} is already {bulletin.status}")
            raise typer.Exit(code=1)

        now = datetime.now(UTC)
        bulletin.analyst = analyst
        bulletin.reviewed_at = now
        if reject:
            bulletin.status = BulletinStatus.REJECTED
            typer.echo(f"bulletin {bulletin_id} rejected by {analyst}")
        else:
            bulletin.status = BulletinStatus.ISSUED
            bulletin.issued_at = now
            typer.echo(f"bulletin {bulletin_id} issued by {analyst}")


# --------------------------------------------------------------------------
# delivery
# --------------------------------------------------------------------------


@delivery_app.command("add")
def delivery_add(
    slug: Annotated[str, typer.Argument(help="Tenant slug.")],
    label: Annotated[str, typer.Option(help="Human label, e.g. 'SOC on-call'.")],
    channel: Annotated[DeliveryChannel, typer.Option(help="slack or teams.")],
    secret_name: Annotated[str, typer.Option(help="Vault key holding the webhook URL (spec §11).")],
    min_tier: Annotated[Tier | None, typer.Option(help="Only send at or above this tier.")] = None,
    include_reviewed: Annotated[
        bool, typer.Option(help="Also send analyst-released bulletins.")
    ] = True,
) -> None:
    """Register a destination for a tenant's issued bulletins (spec §12).

    The webhook URL itself is never stored here - only the name of the
    secret that holds it.
    """
    with session_for_control() as session:
        tenant = get_tenant(session, slug)
        session.add(
            DeliveryDestination(
                tenant_id=tenant.tenant_id,
                channel=channel,
                label=label,
                webhook_secret_name=secret_name,
                min_tier=min_tier,
                include_reviewed=include_reviewed,
            )
        )
    typer.echo(f"added {channel} destination {label!r} for {slug}")

    store = build_secret_store()
    if store.get_optional(secret_name) is None:
        typer.echo(
            f"  warning: secret {secret_name!r} is not present yet; "
            "delivery will fail until it is set"
        )


@delivery_app.command("list")
def delivery_list(
    slug: Annotated[str, typer.Argument(help="Tenant slug.")],
) -> None:
    """List a tenant's destinations and whether their secrets resolve."""
    store = build_secret_store()
    with session_for_control() as session:
        tenant = get_tenant(session, slug)
        destinations = session.scalars(
            select(DeliveryDestination).where(DeliveryDestination.tenant_id == tenant.tenant_id)
        ).all()

        if not destinations:
            typer.echo("no destinations")
            return
        for item in destinations:
            present = store.get_optional(item.webhook_secret_name) is not None
            typer.echo(
                f"  #{item.id:<3} {item.channel:<6} {item.label:<24} "
                f"min_tier={item.min_tier or 'any':<9} active={item.active} "
                f"secret={'set' if present else 'MISSING'}"
            )


@delivery_app.command("send")
def delivery_send(
    slug: Annotated[str | None, typer.Option(help="One tenant instead of all.")] = None,
) -> None:
    """Send issued bulletins to their destinations (spec §12)."""
    results = [deliver_for_tenant(slug)] if slug else list(deliver_all_tenants())

    failures = 0
    for item in results:
        outcome = item.result
        marker = "ok " if item.ok else "FAIL"
        typer.echo(
            f"{marker} {item.slug:<16} considered={outcome.considered:<5} "
            f"sent={outcome.sent:<5} failed={outcome.failed:<5} "
            f"skipped={outcome.skipped}" + (f"  {item.error}" if item.error else "")
        )
        for label in outcome.misconfigured:
            typer.echo(f"     missing secret for destination {label!r}")
        failures += 0 if item.ok else 1

    if failures:
        raise typer.Exit(code=1)


# --------------------------------------------------------------------------
# audit
# --------------------------------------------------------------------------


@audit_app.command("tail")
def audit_tail(
    slug: Annotated[str | None, typer.Option(help="Only this tenant's events.")] = None,
    denials_only: Annotated[bool, typer.Option(help="Only refused attempts.")] = False,
    limit: Annotated[int, typer.Option(help="Maximum rows.")] = 50,
) -> None:
    """Read the audit trail (spec §11)."""
    with audit_trail() as trail:
        events = (
            trail.denials(limit=limit)
            if denials_only
            else trail.events_for_tenant(slug, limit=limit)
            if slug
            else trail.denials(limit=limit)
        )
        if not events:
            typer.echo("no events")
            return
        for event in events:
            marker = "DENIED" if event.outcome is AuditOutcome.DENIED else "ok    "
            typer.echo(
                f"  {event.occurred_at:%Y-%m-%d %H:%M:%S}Z {marker} "
                f"{event.subject:<28} {event.action:<20} "
                f"{event.tenant_slug or '-':<12} {event.permission or ''}"
            )
            if event.reason:
                typer.echo(f"        {event.reason}")


# --------------------------------------------------------------------------
# db
# --------------------------------------------------------------------------


@db_app.command("grants")
def db_grants(
    apply: Annotated[
        bool, typer.Option(help="Execute the statements instead of printing them.")
    ] = False,
    create_roles: Annotated[
        bool, typer.Option(help="Create the roles if they do not exist.")
    ] = False,
) -> None:
    """Make the shared intel store read-only to tenant workers (spec §11).

    Prints the SQL by default so it can be reviewed or put in a change
    ticket; ``--apply`` runs it.
    """
    if not apply:
        for statement in grant_statements():
            typer.echo(f"{statement};")
        return

    applied = apply_grants(engine=get_engine(), create_roles=create_roles)
    typer.echo(f"applied {len(applied)} statements")


@app.command("serve")
def serve(
    host: Annotated[str, typer.Option(help="Bind address.")] = "127.0.0.1",
    port: Annotated[int, typer.Option(help="Bind port.")] = 8000,
    reload: Annotated[bool, typer.Option(help="Reload on code changes.")] = False,
) -> None:
    """Run the tenant API (spec §12).

    Refuses to start without SSO configured: an API that cannot
    authenticate would reject every request, and an operator should learn
    that at startup rather than from user reports.
    """
    import uvicorn

    settings = get_settings()
    if not settings.oidc_issuer:
        typer.echo(
            "AEGIS_OIDC_ISSUER is not set: the API cannot authenticate anyone.",
            err=True,
        )
        raise typer.Exit(code=1)

    uvicorn.run(
        "aegis.api.app:create_app",
        factory=True,
        host=host,
        port=port,
        reload=reload,
    )


def _render_range(cpe: AffectedCpe) -> str:
    if cpe.version_exact:
        return f"== {cpe.version_exact}"
    bounds = []
    if cpe.version_start_including:
        bounds.append(f">={cpe.version_start_including}")
    if cpe.version_start_excluding:
        bounds.append(f">{cpe.version_start_excluding}")
    if cpe.version_end_including:
        bounds.append(f"<={cpe.version_end_including}")
    if cpe.version_end_excluding:
        bounds.append(f"<{cpe.version_end_excluding}")
    return " ".join(bounds) if bounds else "(all versions)"


#: Settings whose value is itself a secret and is never printed.
_SECRET_SETTINGS = ("key", "token", "password", "secret")


def _present(name: str, value: object) -> str:
    """Render a setting for display, withholding anything secret.

    A credential is replaced outright.  A URL or DSN is kept - knowing which
    host is configured is the point of the command - but any credentials
    embedded in it are stripped.
    """
    if value is None:
        return "None"

    text = str(value)
    if any(marker in name for marker in _SECRET_SETTINGS):
        return "***set***" if text and text != "None" else "None"
    if "://" in text:
        return _strip_credentials(text)
    return text


def _strip_credentials(url: str) -> str:
    """Remove ``user:password@`` from a URL, keeping scheme, host and path."""
    scheme, separator, rest = url.partition("://")
    if "@" not in rest:
        return url
    _, _, host = rest.rpartition("@")
    return f"{scheme}{separator}***@{host}"


if __name__ == "__main__":  # pragma: no cover
    app()
