"""``aegis`` command line - operating the intel core."""

from __future__ import annotations

from typing import Annotated

import structlog
import typer
from sqlalchemy import desc, func, select

from aegis.config import get_settings
from aegis.core.enums import ExploitStatus, FeedSource, RunStatus
from aegis.db.base import session_scope
from aegis.db.models import AffectedCpe, FeedRun, IntelRecord, IntelSource
from aegis.intel.runner import run_pipeline, run_pipelines
from aegis.logging import configure_logging

log = structlog.get_logger(__name__)

app = typer.Typer(
    help="Aegis intel core - deterministic feed ETL over the shared intel store.",
    no_args_is_help=True,
    add_completion=False,
)
intel_app = typer.Typer(help="Shared intel store operations.", no_args_is_help=True)
app.add_typer(intel_app, name="intel")


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
