"""
sentinelai/cli.py
─────────────────
SentinelAI Command-Line Interface (Section 8.1, 12, Phase 6a & Phase 8).

Commands:
- ingest: Ingest threat intelligence knowledge base (MITRE, IOCs, CVEs, malware, patterns).
- investigate: Execute end-to-end multi-agent investigation on incident JSON.
- feedback: Record human analyst verdict for RL triage reward signal.
"""
from __future__ import annotations

import json
from pathlib import Path
import click

from sentinelai.interfaces.feedback import record_feedback
from sentinelai.investigation import investigate as run_investigate
from sentinelai.schemas import AnalystFeedback, IncidentInput
from sentinelai.threat_intel.chroma_store import ThreatIntelChromaStore
from sentinelai.threat_intel.duckdb_store import ThreatIntelDuckDBStore
from sentinelai.threat_intel.ingest import ThreatIntelIngester


@click.group()
def main() -> None:
    """SentinelAI — Autonomous Multi-Agent SOC Investigation Tier."""
    pass


@main.command(name="ingest")
@click.option(
    "--corpus",
    "-c",
    default="all",
    type=click.Choice(["all", "mitre", "ioc", "cve", "malware", "pattern"], case_sensitive=False),
    help="Target corpus branch to ingest.",
)
@click.option(
    "--offline-seed/--no-offline-seed",
    default=True,
    help="Ingest bundled offline seed files.",
)
@click.option(
    "--db-path",
    default=None,
    help="DuckDB database path (defaults to in-memory or config).",
)
@click.option(
    "--chroma-dir",
    default=None,
    help="Chroma persistence directory.",
)
def ingest(
    corpus: str,
    offline_seed: bool,
    db_path: str | None,
    chroma_dir: str | None,
) -> None:
    """Ingest threat intelligence data into DuckDB and Chroma collections (Section 12 Phase 6a)."""
    duck_store = ThreatIntelDuckDBStore(db_path or ":memory:")
    chroma_store = ThreatIntelChromaStore(persist_directory=chroma_dir)
    ingester = ThreatIntelIngester(duck_store, chroma_store)

    c_choice = corpus.lower()
    results: dict[str, int] = {}

    if c_choice in ("all", "pattern"):
        results["patterns"] = ingester.ingest_patterns()
    if c_choice in ("all", "ioc"):
        results["iocs"] = ingester.ingest_iocs()
    if c_choice in ("all", "cve"):
        results["cves"] = ingester.ingest_cves()
    if c_choice in ("all", "mitre"):
        results["mitre"] = ingester.ingest_mitre()
    if c_choice in ("all", "malware"):
        results["malware"] = ingester.ingest_malware()

    click.echo("Ingestion completed successfully:")
    for k, v in results.items():
        click.echo(f"  - {k}: {v} records")


@main.command(name="investigate")
@click.argument("incident_path", type=click.Path(exists=True, dir_okay=False))
@click.option(
    "--out",
    "-o",
    default="reports",
    help="Output directory for generated markdown report and trace JSON.",
)
@click.option(
    "--max-loops",
    default=2,
    help="Maximum validation loops before forcing low-confidence completion.",
)
def investigate_cmd(incident_path: str, out: str, max_loops: int) -> None:
    """Execute autonomous investigation on an incident JSON file (Section 9 & 12 Phase 8)."""
    path = Path(incident_path)
    data = json.loads(path.read_text(encoding="utf-8"))
    incident = IncidentInput.model_validate(data)

    click.echo(f"Starting investigation for incident: {incident.incident_id} (Risk: {incident.risk_level.value})")

    report = run_investigate(
        incident=incident,
        out_dir=out,
        max_validation_loops=max_loops,
    )

    incident_dir = Path(out) / incident.incident_id
    click.echo("Investigation completed successfully:")
    click.echo(f"  Incident ID:        {report.incident_id}")
    click.echo(f"  Overall Confidence: {report.overall_confidence:.2f}")
    click.echo(f"  Validated Findings: {len(report.findings)}")
    click.echo(f"  Report saved to:    {incident_dir / 'report.md'}")
    click.echo(f"  Trace saved to:     {incident_dir / 'trace.json'}")


@main.command(name="feedback")
@click.argument("incident_id")
@click.option(
    "--verdict",
    "-v",
    required=True,
    type=click.Choice(["true_positive", "false_positive", "needs_more_work"]),
    help="Analyst ground-truth assessment.",
)
@click.option(
    "--severity-correct/--severity-wrong",
    default=True,
    help="Whether initial triage severity was appropriate.",
)
@click.option(
    "--notes",
    "-n",
    default="",
    help="Analyst commentary or remediation notes.",
)
@click.option(
    "--out",
    "-o",
    default="reports",
    help="Reports and traces root directory.",
)
def feedback_cmd(
    incident_id: str,
    verdict: str,
    severity_correct: bool,
    notes: str,
    out: str,
) -> None:
    """Submit analyst feedback for an incident (RL reward update signal, Section 9)."""
    fb = AnalystFeedback(
        incident_id=incident_id,
        verdict=verdict,
        severity_correct=severity_correct,
        notes=notes,
    )
    fb_path = record_feedback(fb, trace_dir=out)
    click.echo(f"Analyst feedback recorded successfully for incident {incident_id}:")
    click.echo(f"  Verdict:  {verdict}")
    click.echo(f"  File:     {fb_path}")


if __name__ == "__main__":
    main()
