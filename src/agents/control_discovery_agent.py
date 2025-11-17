"""
Control Discovery Agent

Orchestrates discovery of security controls from multiple sources,
deduplicates, matches to risks, and performs gap analysis.
"""

from typing import Dict, List, Optional
import asyncio
import logging
from concurrent.futures import ThreadPoolExecutor, as_completed

from src.tools.confluence_adapter import ConfluenceAdapter
from src.tools.jira_adapter import JiraAdapter
from src.tools.servicenow_grc_adapter import ServiceNowGRCAdapter
from src.tools.filesystem_control_scanner import FilesystemControlScanner
from src.tools.control_deduplicator import ControlDeduplicator
from src.tools.control_risk_matcher import ControlRiskMatcher
from src.tools.gap_analyzer import GapAnalyzer

logger = logging.getLogger(__name__)


class ControlDiscoveryAgent:
    """Agent for discovering and analyzing security controls."""

    def __init__(self, config: Optional[Dict] = None):
        """
        Initialize control discovery agent.

        Args:
            config: Configuration dictionary
        """
        self.config = config or {}

        # Initialize adapters
        self.confluence = ConfluenceAdapter(mock_mode=True)
        self.jira = JiraAdapter(mock_mode=True)
        self.servicenow = ServiceNowGRCAdapter(mock_mode=True)
        self.filesystem_scanner = FilesystemControlScanner()

        # Initialize analyzers
        self.deduplicator = ControlDeduplicator(similarity_threshold=0.8)
        self.matcher = ControlRiskMatcher()
        self.gap_analyzer = GapAnalyzer()

        logger.info("Initialized ControlDiscoveryAgent")

    def discover_controls(self, sources: Optional[List[str]] = None,
                         frameworks: Optional[List[str]] = None) -> Dict:
        """
        Discover controls from multiple sources in parallel.

        Args:
            sources: List of sources to query ['confluence', 'jira', 'servicenow', 'filesystem']
            frameworks: Filter by frameworks ['NIST', 'CIS', 'ISO27001']

        Returns:
            Dictionary with discovered controls and metadata
        """
        sources = sources or ['confluence', 'jira', 'servicenow']
        logger.info(f"Discovering controls from sources: {sources}")

        all_controls = []
        source_stats = {}

        # Parallel discovery using ThreadPoolExecutor
        with ThreadPoolExecutor(max_workers=4) as executor:
            futures = {}

            if 'confluence' in sources:
                futures[executor.submit(self._discover_confluence, frameworks)] = 'confluence'

            if 'jira' in sources:
                futures[executor.submit(self._discover_jira, frameworks)] = 'jira'

            if 'servicenow' in sources:
                futures[executor.submit(self._discover_servicenow, frameworks)] = 'servicenow'

            if 'filesystem' in sources:
                scan_path = self.config.get('filesystem_scan_path', './docs')
                futures[executor.submit(self._discover_filesystem, scan_path, frameworks)] = 'filesystem'

            # Collect results
            for future in as_completed(futures):
                source_name = futures[future]
                try:
                    controls = future.result()
                    all_controls.extend(controls)
                    source_stats[source_name] = len(controls)
                    logger.info(f"Discovered {len(controls)} controls from {source_name}")
                except Exception as e:
                    logger.error(f"Error discovering from {source_name}: {e}")
                    source_stats[source_name] = 0

        logger.info(f"Total controls discovered: {len(all_controls)}")

        return {
            'controls': all_controls,
            'total_count': len(all_controls),
            'by_source': source_stats,
            'by_framework': self._count_by_framework(all_controls)
        }

    def run_full_analysis(self, risks: List[Dict],
                         sources: Optional[List[str]] = None,
                         frameworks: Optional[List[str]] = None) -> Dict:
        """
        Run complete control discovery and gap analysis workflow.

        Workflow:
        1. Discover controls from all sources (parallel)
        2. Deduplicate controls
        3. Match controls to risks
        4. Analyze gaps
        5. Generate recommendations

        Args:
            risks: List of identified risks to analyze
            sources: Sources to query
            frameworks: Frameworks to filter

        Returns:
            Comprehensive analysis report
        """
        logger.info("=" * 80)
        logger.info("STARTING FULL CONTROL DISCOVERY AND GAP ANALYSIS")
        logger.info("=" * 80)

        # Step 1: Discover controls
        logger.info("\n[Step 1/5] Discovering controls from sources...")
        discovery_result = self.discover_controls(sources, frameworks)
        raw_controls = discovery_result['controls']

        # Step 2: Deduplicate
        logger.info(f"\n[Step 2/5] Deduplicating {len(raw_controls)} controls...")
        unique_controls = self.deduplicator.deduplicate_controls(raw_controls)
        logger.info(f"Reduced to {len(unique_controls)} unique controls")

        # Step 3: Match to risks
        logger.info(f"\n[Step 3/5] Matching {len(unique_controls)} controls to {len(risks)} risks...")
        matching_result = self.matcher.match_controls_to_risks(unique_controls, risks)

        # Step 4: Gap analysis
        logger.info("\n[Step 4/5] Performing gap analysis...")
        gap_analysis = self.gap_analyzer.analyze_gaps(
            risks,
            unique_controls,
            matching_result['risk_control_mapping']
        )

        # Step 5: Compile results
        logger.info("\n[Step 5/5] Compiling final report...")

        final_report = {
            'summary': {
                'total_controls_discovered': len(raw_controls),
                'unique_controls': len(unique_controls),
                'duplicates_removed': len(raw_controls) - len(unique_controls),
                'total_risks_analyzed': len(risks),
                'coverage_percentage': matching_result['coverage_metrics']['overall_coverage_percentage'],
                'gap_score': gap_analysis['gap_score'],
                'risks_without_controls': gap_analysis['summary']['uncovered_count']
            },
            'discovery': discovery_result,
            'controls': unique_controls,
            'matching': matching_result,
            'gap_analysis': gap_analysis,
            'top_recommendations': gap_analysis['recommendations'][:5]
        }

        logger.info("\n" + "=" * 80)
        logger.info("ANALYSIS COMPLETE")
        logger.info(f"Coverage: {final_report['summary']['coverage_percentage']}%")
        logger.info(f"Gap Score: {final_report['summary']['gap_score']}/100")
        logger.info(f"Uncovered Risks: {final_report['summary']['risks_without_controls']}")
        logger.info("=" * 80 + "\n")

        return final_report

    def _discover_confluence(self, frameworks: Optional[List[str]]) -> List[Dict]:
        """Discover controls from Confluence."""
        controls = self.confluence.search_controls(query="", frameworks=frameworks)
        # Convert to dict format
        return [self._normalize_control(c.__dict__, 'confluence') for c in controls]

    def _discover_jira(self, frameworks: Optional[List[str]]) -> List[Dict]:
        """Discover controls from Jira."""
        issues = self.jira.search_issues()
        controls = []
        for issue in issues:
            issue_controls = self.jira.get_issue_controls(issue.issue_key)
            controls.extend(issue_controls)
        return controls

    def _discover_servicenow(self, frameworks: Optional[List[str]]) -> List[Dict]:
        """Discover controls from ServiceNow GRC."""
        filters = {'framework': frameworks[0]} if frameworks and len(frameworks) == 1 else None
        snow_controls = self.servicenow.query_grc_controls(filters)
        return [self._normalize_control(c.__dict__, 'servicenow') for c in snow_controls]

    def _discover_filesystem(self, path: str, frameworks: Optional[List[str]]) -> List[Dict]:
        """Discover controls from filesystem."""
        try:
            file_controls = self.filesystem_scanner.scan_directory(path, frameworks, recursive=True)
            return [self._normalize_control(c.__dict__, 'filesystem') for c in file_controls]
        except Exception as e:
            logger.warning(f"Filesystem scan failed: {e}")
            return []

    def _normalize_control(self, control_dict: Dict, source: str) -> Dict:
        """Normalize control dictionary to standard format."""
        return {
            'control_id': control_dict.get('control_id', ''),
            'framework': control_dict.get('framework', ''),
            'title': control_dict.get('title', ''),
            'description': control_dict.get('description', ''),
            'source': source,
            'confidence': control_dict.get('confidence', 0.75),
            'implementation_status': control_dict.get('implementation_status',
                                                     control_dict.get('status', 'unknown')),
            'owner': control_dict.get('owner', ''),
            'evidence': control_dict.get('evidence', ''),
            'metadata': control_dict.get('metadata', {})
        }

    def _count_by_framework(self, controls: List[Dict]) -> Dict:
        """Count controls by framework."""
        counts = {}
        for control in controls:
            framework = control.get('framework', 'Unknown')
            counts[framework] = counts.get(framework, 0) + 1
        return counts
