"""
sentinelai/threat_intel/ingest.py
─────────────────────────────────
Offline seed data ingestion pipeline (Section 8.1 - 8.3 & Section 12 Phase 6a/6b).
Populates DuckDB tables (iocs, cves, intel_links, intel_metadata) and Chroma collections
(mitre, cves, malware, patterns) with 100% idempotency.
"""
from __future__ import annotations

import json
from pathlib import Path
import re
from typing import Any

from sentinelai.threat_intel.chroma_store import ThreatIntelChromaStore
from sentinelai.threat_intel.duckdb_store import ThreatIntelDuckDBStore
from sentinelai.threat_intel.normalization import normalize_ioc
from sentinelai.threat_intel.schemas import (
    IntelDocument,
    IntelSource,
    IOCType,
)


def _parse_markdown_frontmatter(content: str) -> tuple[dict[str, Any], str]:
    """Parse YAML frontmatter and body from Markdown."""
    meta: dict[str, Any] = {}
    body = content

    if content.startswith("---"):
        parts = content.split("---", 2)
        if len(parts) >= 3:
            fm_text = parts[1].strip()
            body = parts[2].strip()

            current_key = None
            for line in fm_text.splitlines():
                line_str = line.strip()
                if not line_str or line_str.startswith("#"):
                    continue
                if ":" in line_str and not line_str.startswith("-"):
                    k, v = line_str.split(":", 1)
                    current_key = k.strip()
                    val = v.strip()
                    if val == "[]":
                        meta[current_key] = []
                    elif val:
                        meta[current_key] = val.strip("'\"")
                    else:
                        meta[current_key] = []
                elif line_str.startswith("-") and current_key:
                    item_val = line_str.lstrip("-").strip().strip("'\"")
                    if isinstance(meta.get(current_key), list):
                        meta[current_key].append(item_val)

    return meta, body


class ThreatIntelIngester:
    """
    Ingestion engine for all 5 corpora branches.
    """

    def __init__(
        self,
        duck_store: ThreatIntelDuckDBStore,
        chroma_store: ThreatIntelChromaStore,
        seed_dir: Path | str | None = None,
    ) -> None:
        self.duck_store = duck_store
        self.chroma_store = chroma_store
        self.seed_dir = Path(seed_dir) if seed_dir else Path(__file__).parent.parent.parent / "rag" / "seed_data"

    def ingest_patterns(self) -> int:
        """Ingest attack pattern playbooks."""
        pattern_dir = self.seed_dir / "patterns"
        if not pattern_dir.exists():
            return 0

        docs: list[IntelDocument] = []
        for p_file in sorted(pattern_dir.glob("*.md")):
            text = p_file.read_text(encoding="utf-8")
            meta, body = _parse_markdown_frontmatter(text)
            slug = meta.get("slug", p_file.stem)
            title = meta.get("title", slug.replace("_", " ").title())
            doc_id = f"pattern:{slug}"

            doc = IntelDocument(
                doc_id=doc_id,
                corpus=IntelSource.PATTERN,
                title=title,
                text=f"{title}\n\n{body}",
                metadata=meta,
                corpus_version="v1",
            )
            docs.append(doc)
            self.duck_store.insert_metadata(doc)

            # Insert link to MITRE techniques: pattern -> mitre:Txxxx (maps_to)
            techniques = meta.get("mitre_techniques", [])
            if isinstance(techniques, list):
                for tech in techniques:
                    self.duck_store.insert_link(doc_id, f"mitre:{tech}", "maps_to")

        self.chroma_store.add_documents(IntelSource.PATTERN, docs)
        return len(docs)

    def ingest_iocs(self) -> int:
        """Ingest and normalize IOCs into DuckDB."""
        ioc_path = self.seed_dir / "iocs" / "seed_iocs.json"
        if not ioc_path.exists():
            return 0

        raw_iocs = json.loads(ioc_path.read_text(encoding="utf-8"))
        count = 0
        for item in raw_iocs:
            raw_kind = item.get("ioc_type", "domain")
            raw_val = item.get("value", "")
            try:
                norm_kind, norm_val = normalize_ioc(raw_kind, raw_val)
            except Exception:
                continue

            doc_id = f"ioc:{norm_kind.value}:{norm_val}"
            self.duck_store.insert_ioc(
                ioc_type=norm_kind,
                value_normalized=norm_val,
                source=item.get("source", "seed"),
                first_seen=item.get("first_seen"),
                last_seen=item.get("last_seen"),
                confidence=float(item.get("confidence", 0.8)),
                tags=item.get("tags", []),
                malware_family=item.get("malware_family"),
                reference_url=item.get("reference_url"),
            )

            # Link IOC to malware family if present
            fam = item.get("malware_family")
            if fam:
                self.duck_store.insert_link(doc_id, f"malware:{fam.lower().replace(' ', '_')}", "associated_with")

            count += 1
        return count

    def ingest_cves(self) -> int:
        """Ingest CVEs into DuckDB and Chroma."""
        cve_path = self.seed_dir / "cves" / "seed_cves.json"
        if not cve_path.exists():
            return 0

        cves = json.loads(cve_path.read_text(encoding="utf-8"))
        docs: list[IntelDocument] = []
        for item in cves:
            cve_id = item["cve_id"].strip().upper()
            doc_id = f"cve:{cve_id}"

            self.duck_store.insert_cve(
                cve_id=cve_id,
                description=item["description"],
                cvss_score=item.get("cvss_score"),
                cvss_vector=item.get("cvss_vector"),
                cwe=item.get("cwe"),
                published_date=item.get("published_date"),
                modified_date=item.get("modified_date"),
                kev_flag=bool(item.get("kev_flag", False)),
                affected_products=item.get("affected_products", []),
                references=item.get("references", []),
            )

            doc = IntelDocument(
                doc_id=doc_id,
                corpus=IntelSource.CVE,
                title=f"CVE: {cve_id}",
                text=f"{cve_id}: {item['description']}",
                metadata={
                    "cve_id": cve_id,
                    "cvss_score": float(item.get("cvss_score") or 0.0),
                    "kev_flag": bool(item.get("kev_flag", False)),
                },
                source_url=item.get("references", [None])[0] if item.get("references") else None,
                corpus_version="v1",
            )
            docs.append(doc)
            self.duck_store.insert_metadata(doc)

        self.chroma_store.add_documents(IntelSource.CVE, docs)
        return len(docs)

    def ingest_mitre(self) -> int:
        """Ingest MITRE techniques, parent relations, and detection guidance."""
        mitre_path = self.seed_dir / "mitre" / "seed_mitre.json"
        if not mitre_path.exists():
            return 0

        techniques = json.loads(mitre_path.read_text(encoding="utf-8"))
        docs: list[IntelDocument] = []
        for item in techniques:
            t_id = item["technique_id"].strip()
            name = item["name"].strip()
            doc_id = f"mitre:{t_id}"

            full_text = f"{t_id} {name}: {item['description']}\nDetection: {item.get('detection', '')}"
            doc = IntelDocument(
                doc_id=doc_id,
                corpus=IntelSource.MITRE,
                title=f"{t_id}: {name}",
                text=full_text,
                metadata={
                    "technique_id": t_id,
                    "name": name,
                    "is_subtechnique": bool(item.get("is_subtechnique", False)),
                    "parent_id": item.get("parent_id") or "",
                    "tactics": ", ".join(item.get("tactics", [])),
                },
                source_url=item.get("url"),
                corpus_version="v1",
            )
            docs.append(doc)
            self.duck_store.insert_metadata(doc)

            # Link parent of subtechnique
            parent_id = item.get("parent_id")
            if parent_id:
                self.duck_store.insert_link(f"mitre:{parent_id}", doc_id, "parent_of")

        self.chroma_store.add_documents(IntelSource.MITRE, docs)
        return len(docs)

    def ingest_malware(self) -> int:
        """Ingest malware objects, behaviors, and technique linkages."""
        malware_path = self.seed_dir / "malware" / "seed_malware.json"
        if not malware_path.exists():
            return 0

        malwares = json.loads(malware_path.read_text(encoding="utf-8"))
        docs: list[IntelDocument] = []
        for item in malwares:
            m_id = item["malware_id"].strip()
            name = item["name"].strip()
            doc_id = f"malware:{m_id}"

            behaviors = "\n- ".join(item.get("behaviors", []))
            full_text = f"{m_id} {name}: {item['description']}\nBehaviors:\n- {behaviors}"

            doc = IntelDocument(
                doc_id=doc_id,
                corpus=IntelSource.MALWARE,
                title=f"{m_id}: {name}",
                text=full_text,
                metadata={
                    "malware_id": m_id,
                    "name": name,
                    "aliases": ", ".join(item.get("aliases", [])),
                },
                source_url=item.get("url"),
                corpus_version="v1",
            )
            docs.append(doc)
            self.duck_store.insert_metadata(doc)

            # Link techniques used by malware: mitre:Txxxx -> malware:Sxxxx (used_by)
            techs = item.get("techniques_used", [])
            for t in techs:
                self.duck_store.insert_link(f"mitre:{t}", doc_id, "used_by")

        self.chroma_store.add_documents(IntelSource.MALWARE, docs)
        return len(docs)

    def ingest_all(self) -> dict[str, int]:
        """Ingest all 5 corpora branches."""
        patterns_cnt = self.ingest_patterns()
        iocs_cnt = self.ingest_iocs()
        cves_cnt = self.ingest_cves()
        mitre_cnt = self.ingest_mitre()
        malware_cnt = self.ingest_malware()

        return {
            "patterns": patterns_cnt,
            "iocs": iocs_cnt,
            "cves": cves_cnt,
            "mitre": mitre_cnt,
            "malware": malware_cnt,
        }
