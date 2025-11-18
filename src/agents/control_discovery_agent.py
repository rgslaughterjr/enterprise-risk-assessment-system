"""Control Discovery Agent for comprehensive control discovery and gap analysis.

This agent orchestrates the control discovery workflow including:
- Multi-source control discovery (Confluence, ServiceNow GRC, filesystem)
- Control deduplication using TF-IDF
- Control-to-risk mapping
- Coverage gap analysis
- Prioritized remediation recommendations
"""

import os
import logging
from typing import List, Dict, Optional, Any
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from pathlib import Path

from ..tools.confluence_adapter import ConfluenceAdapter
from ..tools.servicenow_grc_adapter import ServiceNowGRCAdapter
from ..tools.filesystem_control_scanner import FilesystemControlScanner
from ..tools.control_deduplicator import ControlDeduplicator
from ..tools.control_risk_matcher import ControlRiskMatcher
from ..tools.gap_analyzer import GapAnalyzer

logger = logging.getLogger(__name__)


class ControlDiscoveryAgent:
    """Enterprise-grade control discovery agent.

    Orchestrates comprehensive control discovery workflow:
    1. Parallel discovery from multiple sources
    2. Control deduplication and enrichment
    3. Risk mapping and coverage analysis
    4. Gap identification and prioritization
    5. Actionable recommendations generation
    """

    def __init__(
        self,
        mock_mode: bool = True,
        max_workers: int = 3,
    ):
        """Initialize control discovery agent.

        Args:
            mock_mode: If True, use mock data for testing
            max_workers: Maximum number of parallel workers for source queries
        """
        self.mock_mode = mock_mode
        self.max_workers = max_workers

        # Initialize adapters
        self.confluence_adapter = ConfluenceAdapter(mock_mode=mock_mode)
        self.servicenow_adapter = ServiceNowGRCAdapter(mock_mode=mock_mode)
        self.filesystem_scanner = FilesystemControlScanner()

        # Initialize processing tools
        self.deduplicator = ControlDeduplicator(similarity_threshold=0.85)
        self.matcher = ControlRiskMatcher(similarity_threshold=0.3)
        self.gap_analyzer = GapAnalyzer()

        # Discovery state
        self.discovered_controls = []
        self.unique_controls = []
        self.control_mappings = []
        self.gap_analysis = {}

        logger.info(f"Control Discovery Agent initialized (mock_mode={mock_mode}, max_workers={max_workers})")

    def discover_controls(
        self,
        sources: Optional[List[str]] = None,
        confluence_spaces: Optional[List[str]] = None,
        servicenow_filters: Optional[Dict[str, str]] = None,
        filesystem_paths: Optional[List[str]] = None,
    ) -> List[Dict[str, Any]]:
        """Discover controls from multiple sources in parallel.

        Args:
            sources: List of sources to query (default: all sources)
                    Options: 'confluence', 'servicenow', 'filesystem'
            confluence_spaces: List of Confluence space keys to search
            servicenow_filters: Filters for ServiceNow GRC query
            filesystem_paths: List of filesystem paths to scan

        Returns:
            List of discovered control dictionaries

        Example:
            >>> agent = ControlDiscoveryAgent()
            >>> controls = agent.discover_controls(
            ...     sources=['confluence', 'servicenow'],
            ...     confluence_spaces=['SEC', 'COMP']
            ... )
        """
        if sources is None:
            sources = ['confluence', 'servicenow', 'filesystem']

        logger.info(f"Starting control discovery from sources: {sources}")

        # Prepare discovery tasks
        discovery_tasks = []

        if 'confluence' in sources:
            spaces = confluence_spaces or ['SEC']
            for space in spaces:
                discovery_tasks.append(('confluence', space, None))

        if 'servicenow' in sources:
            filters = servicenow_filters or {}
            discovery_tasks.append(('servicenow', None, filters))

        if 'filesystem' in sources:
            paths = filesystem_paths or ['./docs', './compliance']
            for path in paths:
                if Path(path).exists():
                    discovery_tasks.append(('filesystem', path, None))

        # Execute discovery in parallel
        all_controls = []

        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            future_to_task = {}

            for source, param, filters in discovery_tasks:
                future = executor.submit(
                    self._discover_from_source,
                    source,
                    param,
                    filters
                )
                future_to_task[future] = (source, param)

            # Collect results
            for future in as_completed(future_to_task):
                source, param = future_to_task[future]
                try:
                    controls = future.result()
                    all_controls.extend(controls)
                    logger.info(f"Discovered {len(controls)} controls from {source}")
                except Exception as e:
                    logger.error(f"Error discovering from {source}: {str(e)}")

        self.discovered_controls = all_controls
        logger.info(f"Total controls discovered: {len(all_controls)}")

        return all_controls

    def _discover_from_source(
        self,
        source: str,
        param: Optional[str],
        filters: Optional[Dict],
    ) -> List[Dict[str, Any]]:
        """Discover controls from a single source.

        Args:
            source: Source type ('confluence', 'servicenow', 'filesystem')
            param: Source-specific parameter (space key, path, etc.)
            filters: Source-specific filters

        Returns:
            List of discovered controls
        """
        try:
            if source == 'confluence':
                space_key = param
                controls = self.confluence_adapter.get_space_controls(space_key, limit=50)

            elif source == 'servicenow':
                controls = self.servicenow_adapter.query_grc_controls(
                    filters=filters or {},
                    limit=100
                )

            elif source == 'filesystem':
                path = param
                controls = self.filesystem_scanner.scan_and_extract(
                    path,
                    recursive=True
                )

            else:
                logger.warning(f"Unknown source: {source}")
                return []

            return controls

        except Exception as e:
            logger.error(f"Error discovering from {source}: {str(e)}")
            return []

    def deduplicate_and_enrich(
        self,
        controls: Optional[List[Dict[str, Any]]] = None,
    ) -> List[Dict[str, Any]]:
        """Deduplicate discovered controls and enrich with merged metadata.

        Args:
            controls: List of controls to deduplicate (uses discovered_controls if None)

        Returns:
            List of unique controls with enriched metadata

        Example:
            >>> agent = ControlDiscoveryAgent()
            >>> unique = agent.deduplicate_and_enrich(all_controls)
        """
        if controls is None:
            controls = self.discovered_controls

        if not controls:
            logger.warning("No controls to deduplicate")
            return []

        logger.info(f"Deduplicating {len(controls)} controls")

        # Deduplicate
        unique_controls = self.deduplicator.deduplicate_controls(controls)

        # Get deduplication stats
        stats = self.deduplicator.get_deduplication_stats(len(controls), unique_controls)
        logger.info(f"Deduplication stats: {stats}")

        self.unique_controls = unique_controls
        return unique_controls

    def map_to_risks(
        self,
        risks: List[Dict[str, Any]],
        controls: Optional[List[Dict[str, Any]]] = None,
    ) -> List[Dict[str, Any]]:
        """Map controls to risks they mitigate.

        Args:
            risks: List of risk dictionaries to map against
            controls: List of controls (uses unique_controls if None)

        Returns:
            List of control-risk mapping dictionaries

        Example:
            >>> agent = ControlDiscoveryAgent()
            >>> mappings = agent.map_to_risks(all_risks)
        """
        if controls is None:
            controls = self.unique_controls

        if not controls:
            logger.warning("No controls available for risk mapping")
            return []

        if not risks:
            logger.warning("No risks provided for mapping")
            return []

        logger.info(f"Mapping {len(controls)} controls to {len(risks)} risks")

        # Perform mapping
        mappings = self.matcher.match_controls_to_risks(controls, risks)

        self.control_mappings = mappings
        logger.info(f"Created {len(mappings)} control-risk mappings")

        return mappings

    def analyze_coverage(
        self,
        risks: List[Dict[str, Any]],
        controls: Optional[List[Dict[str, Any]]] = None,
        mappings: Optional[List[Dict[str, Any]]] = None,
    ) -> Dict[str, Any]:
        """Analyze control coverage and identify gaps.

        Args:
            risks: List of risk dictionaries
            controls: List of controls (uses unique_controls if None)
            mappings: Control-risk mappings (uses control_mappings if None)

        Returns:
            Comprehensive gap analysis report

        Example:
            >>> agent = ControlDiscoveryAgent()
            >>> analysis = agent.analyze_coverage(all_risks)
        """
        if controls is None:
            controls = self.unique_controls

        if mappings is None:
            mappings = self.control_mappings

        if not controls or not risks:
            logger.warning("Insufficient data for coverage analysis")
            return {}

        logger.info(f"Analyzing coverage for {len(risks)} risks with {len(controls)} controls")

        # Perform gap analysis
        analysis = self.gap_analyzer.analyze_gaps(risks, controls, mappings)

        self.gap_analysis = analysis
        logger.info(f"Coverage analysis complete: {analysis['summary']}")

        return analysis

    def run_full_discovery(
        self,
        risks: List[Dict[str, Any]],
        sources: Optional[List[str]] = None,
        confluence_spaces: Optional[List[str]] = None,
        servicenow_filters: Optional[Dict[str, str]] = None,
        filesystem_paths: Optional[List[str]] = None,
    ) -> Dict[str, Any]:
        """Run complete control discovery workflow.

        Args:
            risks: List of risk dictionaries for mapping and gap analysis
            sources: Sources to discover from
            confluence_spaces: Confluence spaces to search
            servicenow_filters: ServiceNow query filters
            filesystem_paths: Filesystem paths to scan

        Returns:
            Complete discovery report with all stages

        Example:
            >>> agent = ControlDiscoveryAgent()
            >>> report = agent.run_full_discovery(
            ...     risks=all_risks,
            ...     sources=['confluence', 'servicenow']
            ... )
        """
        logger.info("Starting full control discovery workflow")
        start_time = datetime.utcnow()

        # Stage 1: Discover controls from all sources
        logger.info("Stage 1: Control Discovery")
        discovered = self.discover_controls(
            sources=sources,
            confluence_spaces=confluence_spaces,
            servicenow_filters=servicenow_filters,
            filesystem_paths=filesystem_paths,
        )

        # Stage 2: Deduplicate and enrich
        logger.info("Stage 2: Deduplication and Enrichment")
        unique = self.deduplicate_and_enrich(discovered)

        # Stage 3: Map to risks
        logger.info("Stage 3: Risk Mapping")
        mappings = self.map_to_risks(risks, unique)

        # Stage 4: Analyze coverage
        logger.info("Stage 4: Coverage Analysis")
        analysis = self.analyze_coverage(risks, unique, mappings)

        end_time = datetime.utcnow()
        duration = (end_time - start_time).total_seconds()

        # Build comprehensive report
        report = {
            "execution_summary": {
                "start_time": start_time.isoformat(),
                "end_time": end_time.isoformat(),
                "duration_seconds": duration,
                "sources_queried": sources or ['confluence', 'servicenow', 'filesystem'],
                "mock_mode": self.mock_mode,
            },
            "discovery_results": {
                "total_discovered": len(discovered),
                "unique_controls": len(unique),
                "deduplication_rate": (
                    (len(discovered) - len(unique)) / len(discovered) * 100
                    if discovered else 0
                ),
                "controls": unique,
            },
            "risk_mappings": {
                "total_mappings": len(mappings),
                "mappings": mappings,
            },
            "gap_analysis": analysis,
        }

        logger.info(
            f"Full discovery complete in {duration:.1f}s: "
            f"{len(discovered)} discovered → {len(unique)} unique → "
            f"{len(mappings)} mappings → {len(analysis.get('gaps', []))} gaps"
        )

        return report

    def get_discovery_summary(self) -> Dict[str, Any]:
        """Get summary of current discovery state.

        Returns:
            Summary statistics dictionary
        """
        summary = {
            "discovered_count": len(self.discovered_controls),
            "unique_count": len(self.unique_controls),
            "mapping_count": len(self.control_mappings),
            "has_gap_analysis": bool(self.gap_analysis),
        }

        if self.gap_analysis:
            summary["gap_summary"] = self.gap_analysis.get("summary", {})

        return summary

    def export_report(
        self,
        report: Dict[str, Any],
        output_path: str,
        format: str = "json",
    ) -> bool:
        """Export discovery report to file.

        Args:
            report: Discovery report dictionary
            output_path: Output file path
            format: Output format ('json' or 'text')

        Returns:
            True if export successful
        """
        try:
            output_file = Path(output_path)
            output_file.parent.mkdir(parents=True, exist_ok=True)

            if format == "json":
                import json
                with open(output_file, "w") as f:
                    json.dump(report, f, indent=2)

            elif format == "text":
                with open(output_file, "w") as f:
                    self._write_text_report(report, f)

            else:
                logger.error(f"Unsupported format: {format}")
                return False

            logger.info(f"Report exported to {output_path}")
            return True

        except Exception as e:
            logger.error(f"Error exporting report: {str(e)}")
            return False

    def _write_text_report(self, report: Dict[str, Any], file):
        """Write human-readable text report.

        Args:
            report: Report dictionary
            file: File handle to write to
        """
        file.write("=" * 80 + "\n")
        file.write("CONTROL DISCOVERY REPORT\n")
        file.write("=" * 80 + "\n\n")

        # Execution summary
        exec_summary = report.get("execution_summary", {})
        file.write("EXECUTION SUMMARY\n")
        file.write(f"Duration: {exec_summary.get('duration_seconds', 0):.1f} seconds\n")
        file.write(f"Sources: {', '.join(exec_summary.get('sources_queried', []))}\n")
        file.write(f"Mode: {'Mock' if exec_summary.get('mock_mode') else 'Production'}\n\n")

        # Discovery results
        discovery = report.get("discovery_results", {})
        file.write("DISCOVERY RESULTS\n")
        file.write(f"Total Discovered: {discovery.get('total_discovered', 0)}\n")
        file.write(f"Unique Controls: {discovery.get('unique_controls', 0)}\n")
        file.write(f"Deduplication Rate: {discovery.get('deduplication_rate', 0):.1f}%\n\n")

        # Gap analysis summary
        gap_analysis = report.get("gap_analysis", {})
        if gap_analysis:
            summary = gap_analysis.get("summary", {})
            file.write("GAP ANALYSIS SUMMARY\n")
            file.write(f"Total Risks: {summary.get('total_risks', 0)}\n")
            file.write(f"Gaps Identified: {summary.get('gaps_identified', 0)}\n")
            file.write(f"Coverage Rate: {summary.get('coverage_rate', 0):.1f}%\n")
            file.write(f"Avg Coverage Score: {summary.get('average_coverage_score', 0):.2f}\n\n")

            # Top gaps
            gaps = gap_analysis.get("gaps", [])
            if gaps:
                file.write("TOP CONTROL GAPS\n")
                for i, gap in enumerate(gaps[:10], 1):
                    file.write(f"{i}. {gap.get('risk_name')} (Priority: {gap.get('priority', 'Unknown')})\n")
                    file.write(f"   Coverage: {gap.get('coverage_score', 0):.0%}, ")
                    file.write(f"Residual Risk: {gap.get('residual_risk', 'Unknown')}\n")

        file.write("\n" + "=" * 80 + "\n")
