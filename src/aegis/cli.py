"""``aegis`` command line - operating the intel core."""

from __future__ import annotations

from typing import Annotated

import structlog
import typer
from sqlalchemy import desc, func, select

from aegis.config import get_settings
from aegis.core.enums import (
    AutomationPolicy,
    ExploitStatus,
    FeedSource,
    RunStatus,
    Tier,
)
from aegis.db.base import session_scope
from aegis.db.models import (
    AffectedCpe,
    Asset,
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
