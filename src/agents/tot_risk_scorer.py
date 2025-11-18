"""Tree of Thought (ToT) Risk Scorer Agent.

This agent implements multi-branch Tree of Thought reasoning for risk assessment.
It generates multiple parallel evaluation branches using different risk assessment
frameworks, evaluates their quality, prunes low-quality branches, and synthesizes
a weighted consensus score.

Architecture:
1. Branch Generation - Create 5 parallel branches with different strategies
2. Branch Evaluation - Execute each branch with appropriate framework adapter
3. Quality Scoring - Assess quality of each evaluation
4. Pruning - Remove low-quality branches (threshold: 0.6)
5. Consensus - Calculate weighted consensus from high-quality branches
"""

import logging
from typing import Dict, Any, List, Optional
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed

from ..reasoning.branch_generator import BranchGenerator, EvaluationStrategy
from ..reasoning.branch_evaluator import BranchEvaluator
from ..frameworks.nist_ai_rmf_adapter import NISTAIRMFAdapter
from ..frameworks.octave_adapter import OCTAVEAdapter
from ..frameworks.iso31000_adapter import ISO31000Adapter

logger = logging.getLogger(__name__)


class ToTRiskScorerAgent:
    """Tree of Thought Risk Scorer Agent.

    Orchestrates multi-branch risk assessment using parallel evaluation
    strategies and consensus-based scoring.
    """

    DEFAULT_NUM_BRANCHES = 5
    DEFAULT_QUALITY_THRESHOLD = 0.6
    DEFAULT_CONSENSUS_METHOD = "weighted_average"

    def __init__(
        self,
        num_branches: int = DEFAULT_NUM_BRANCHES,
        quality_threshold: float = DEFAULT_QUALITY_THRESHOLD,
        consensus_method: str = DEFAULT_CONSENSUS_METHOD,
        enable_pruning: bool = True,
        enable_parallel: bool = True,
        max_workers: int = 3,
    ):
        """Initialize ToT Risk Scorer Agent.

        Args:
            num_branches: Number of evaluation branches to generate
            quality_threshold: Minimum quality score for branch inclusion
            consensus_method: Method for consensus scoring (weighted_average/median/majority_vote)
            enable_pruning: If True, prune low-quality branches
            enable_parallel: If True, execute branches in parallel
            max_workers: Maximum parallel workers
        """
        self.num_branches = num_branches
        self.quality_threshold = quality_threshold
        self.consensus_method = consensus_method
        self.enable_pruning = enable_pruning
        self.enable_parallel = enable_parallel
        self.max_workers = max_workers

        # Initialize components
        self.branch_generator = BranchGenerator(
            default_strategies=[s.value for s in EvaluationStrategy]
        )

        self.branch_evaluator = BranchEvaluator(
            quality_threshold=quality_threshold,
            enable_pruning=enable_pruning,
        )

        # Initialize framework adapters
        self.framework_adapters = {
            EvaluationStrategy.NIST_AI_RMF.value: NISTAIRMFAdapter(),
            EvaluationStrategy.OCTAVE.value: OCTAVEAdapter(),
            EvaluationStrategy.ISO_31000.value: ISO31000Adapter(),
            EvaluationStrategy.FAIR.value: self._create_fair_adapter(),
            EvaluationStrategy.QUANTITATIVE.value: self._create_quantitative_adapter(),
        }

        logger.info(
            f"ToT Risk Scorer initialized "
            f"(branches={num_branches}, threshold={quality_threshold}, "
            f"method={consensus_method})"
        )

    def score_risk(
        self,
        risk: Dict[str, Any],
        cve: Optional[Dict[str, Any]] = None,
        asset: Optional[Dict[str, Any]] = None,
        context: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Score risk using Tree of Thought multi-branch evaluation.

        Args:
            risk: Risk dictionary (id, title, description)
            cve: CVE vulnerability data
            asset: Asset information
            context: Additional context

        Returns:
            ToT risk assessment with consensus score and branch details
        """
        logger.info(f"Scoring risk {risk.get('id')} using ToT approach")

        start_time = datetime.utcnow()

        # Step 1: Generate branches
        branches = self._generate_branches(risk, context)
        logger.info(f"Generated {len(branches)} evaluation branches")

        # Step 2: Execute branches
        evaluated_branches = self._execute_branches(branches, cve, asset, context)
        logger.info(f"Executed {len(evaluated_branches)} branches")

        # Step 3: Evaluate quality
        quality_scored_branches = self._score_branch_quality(evaluated_branches)
        logger.info("Branch quality scores calculated")

        # Step 4: Prune low-quality branches
        high_quality_branches, pruned_branches = self._prune_branches(
            quality_scored_branches
        )
        logger.info(
            f"Retained {len(high_quality_branches)} branches, "
            f"pruned {len(pruned_branches)}"
        )

        # Step 5: Calculate consensus
        consensus = self._calculate_consensus(high_quality_branches)
        logger.info(f"Consensus score: {consensus['final_score']}")

        # Calculate execution time
        execution_time = (datetime.utcnow() - start_time).total_seconds()

        # Assemble final assessment
        assessment = {
            "risk_id": risk.get("id", "UNKNOWN"),
            "risk_title": risk.get("title", ""),
            "framework": "Tree of Thought (ToT)",
            "overall_score": consensus["final_score"],
            "risk_level": self._score_to_risk_level(consensus["final_score"]),
            "consensus": consensus,
            "branches": {
                "total_generated": len(branches),
                "total_executed": len(evaluated_branches),
                "high_quality": len(high_quality_branches),
                "pruned": len(pruned_branches),
                "quality_threshold": self.quality_threshold,
            },
            "branch_details": self._format_branch_details(
                high_quality_branches, pruned_branches
            ),
            "evaluation_summary": self.branch_evaluator.get_evaluation_summary(
                quality_scored_branches
            ),
            "execution_metrics": {
                "execution_time_seconds": round(execution_time, 2),
                "parallel_execution": self.enable_parallel,
                "num_workers": self.max_workers if self.enable_parallel else 1,
            },
            "confidence": consensus["confidence"],
            "assessed_at": datetime.utcnow().isoformat(),
        }

        return assessment

    def score_multiple_risks(
        self,
        risks: List[Dict[str, Any]],
        cve_mapping: Optional[Dict[str, Dict[str, Any]]] = None,
        asset_mapping: Optional[Dict[str, Dict[str, Any]]] = None,
        context: Optional[Dict[str, Any]] = None,
    ) -> List[Dict[str, Any]]:
        """Score multiple risks using ToT approach.

        Args:
            risks: List of risk dictionaries
            cve_mapping: Dict mapping risk_id to CVE data
            asset_mapping: Dict mapping risk_id to asset data
            context: Shared context

        Returns:
            List of risk assessments
        """
        logger.info(f"Scoring {len(risks)} risks using ToT approach")

        assessments = []

        for risk in risks:
            risk_id = risk.get("id", "UNKNOWN")

            # Get CVE and asset for this risk
            cve = cve_mapping.get(risk_id) if cve_mapping else None
            asset = asset_mapping.get(risk_id) if asset_mapping else None

            # Score risk
            assessment = self.score_risk(risk, cve, asset, context)
            assessments.append(assessment)

        logger.info(f"Completed ToT scoring for {len(assessments)} risks")

        return assessments

    def _generate_branches(
        self,
        risk: Dict[str, Any],
        context: Optional[Dict[str, Any]],
    ) -> List[Dict[str, Any]]:
        """Generate evaluation branches for risk.

        Args:
            risk: Risk dictionary
            context: Context data

        Returns:
            List of branch dictionaries
        """
        logger.debug(f"Generating {self.num_branches} branches for risk")

        branches = self.branch_generator.generate_branches(
            risk=risk,
            num_branches=self.num_branches,
        )

        return branches

    def _execute_branches(
        self,
        branches: List[Dict[str, Any]],
        cve: Optional[Dict[str, Any]],
        asset: Optional[Dict[str, Any]],
        context: Optional[Dict[str, Any]],
    ) -> List[Dict[str, Any]]:
        """Execute all branches using appropriate framework adapters.

        Args:
            branches: List of branch dictionaries
            cve: CVE data
            asset: Asset data
            context: Context data

        Returns:
            Branches with evaluation results
        """
        logger.debug(f"Executing {len(branches)} branches")

        if self.enable_parallel:
            return self._execute_branches_parallel(branches, cve, asset, context)
        else:
            return self._execute_branches_sequential(branches, cve, asset, context)

    def _execute_branches_parallel(
        self,
        branches: List[Dict[str, Any]],
        cve: Optional[Dict[str, Any]],
        asset: Optional[Dict[str, Any]],
        context: Optional[Dict[str, Any]],
    ) -> List[Dict[str, Any]]:
        """Execute branches in parallel.

        Args:
            branches: Branch list
            cve: CVE data
            asset: Asset data
            context: Context data

        Returns:
            Executed branches
        """
        logger.debug(f"Executing branches in parallel (workers={self.max_workers})")

        evaluated_branches = []

        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            # Submit all branches
            future_to_branch = {
                executor.submit(
                    self._execute_single_branch, branch, cve, asset, context
                ): branch
                for branch in branches
            }

            # Collect results
            for future in as_completed(future_to_branch):
                branch = future_to_branch[future]
                try:
                    evaluated_branch = future.result()
                    evaluated_branches.append(evaluated_branch)
                except Exception as e:
                    logger.error(
                        f"Branch {branch['branch_id']} execution failed: {e}"
                    )
                    # Add failed branch with error
                    branch["status"] = "failed"
                    branch["error"] = str(e)
                    evaluated_branches.append(branch)

        return evaluated_branches

    def _execute_branches_sequential(
        self,
        branches: List[Dict[str, Any]],
        cve: Optional[Dict[str, Any]],
        asset: Optional[Dict[str, Any]],
        context: Optional[Dict[str, Any]],
    ) -> List[Dict[str, Any]]:
        """Execute branches sequentially.

        Args:
            branches: Branch list
            cve: CVE data
            asset: Asset data
            context: Context data

        Returns:
            Executed branches
        """
        logger.debug("Executing branches sequentially")

        evaluated_branches = []

        for branch in branches:
            try:
                evaluated_branch = self._execute_single_branch(
                    branch, cve, asset, context
                )
                evaluated_branches.append(evaluated_branch)
            except Exception as e:
                logger.error(f"Branch {branch['branch_id']} execution failed: {e}")
                branch["status"] = "failed"
                branch["error"] = str(e)
                evaluated_branches.append(branch)

        return evaluated_branches

    def _execute_single_branch(
        self,
        branch: Dict[str, Any],
        cve: Optional[Dict[str, Any]],
        asset: Optional[Dict[str, Any]],
        context: Optional[Dict[str, Any]],
    ) -> Dict[str, Any]:
        """Execute a single branch evaluation.

        Args:
            branch: Branch dictionary
            cve: CVE data
            asset: Asset data
            context: Context data

        Returns:
            Branch with evaluation results
        """
        strategy = branch["strategy"]
        branch_id = branch["branch_id"]

        logger.debug(f"Executing branch {branch_id} with strategy {strategy}")

        # Get appropriate adapter
        adapter = self.framework_adapters.get(strategy)

        if not adapter:
            raise ValueError(f"No adapter found for strategy: {strategy}")

        # Merge branch parameters with context
        merged_context = {**(context or {}), **branch["parameters"]}

        # Execute assessment based on strategy
        if strategy == EvaluationStrategy.NIST_AI_RMF.value:
            evaluation = adapter.score_ai_risk(cve, asset, merged_context)
        elif strategy in [
            EvaluationStrategy.OCTAVE.value,
            EvaluationStrategy.ISO_31000.value,
        ]:
            evaluation = adapter.assess_risk(cve, asset, merged_context)
        else:
            # FAIR and Quantitative adapters
            evaluation = adapter.assess_risk(cve, asset, merged_context)

        # Update branch
        branch["evaluation"] = evaluation
        branch["status"] = "completed"

        return branch

    def _score_branch_quality(
        self,
        branches: List[Dict[str, Any]],
    ) -> List[Dict[str, Any]]:
        """Score quality of all branches.

        Args:
            branches: Evaluated branches

        Returns:
            Branches with quality scores
        """
        logger.debug("Scoring branch quality")

        return self.branch_evaluator.evaluate_all_branches(branches)

    def _prune_branches(
        self,
        branches: List[Dict[str, Any]],
    ) -> tuple:
        """Prune low-quality branches.

        Args:
            branches: Quality-scored branches

        Returns:
            Tuple of (high_quality_branches, pruned_branches)
        """
        logger.debug(f"Pruning branches (threshold={self.quality_threshold})")

        return self.branch_evaluator.prune_low_quality(branches)

    def _calculate_consensus(
        self,
        branches: List[Dict[str, Any]],
    ) -> Dict[str, Any]:
        """Calculate consensus score from high-quality branches.

        Args:
            branches: High-quality branches

        Returns:
            Consensus score dictionary
        """
        logger.debug(f"Calculating consensus using {self.consensus_method}")

        return self.branch_evaluator.consensus_scoring(
            branches, method=self.consensus_method
        )

    def _format_branch_details(
        self,
        high_quality_branches: List[Dict[str, Any]],
        pruned_branches: List[Dict[str, Any]],
    ) -> Dict[str, Any]:
        """Format branch details for output.

        Args:
            high_quality_branches: High-quality branches
            pruned_branches: Pruned branches

        Returns:
            Formatted branch details
        """
        high_quality_summary = []
        for branch in high_quality_branches:
            evaluation = branch.get("evaluation", {})
            high_quality_summary.append({
                "branch_id": branch["branch_id"],
                "strategy": branch["strategy"],
                "score": evaluation.get("overall_score"),
                "risk_level": evaluation.get("risk_level"),
                "quality_score": branch.get("quality_score"),
                "framework": evaluation.get("framework"),
            })

        pruned_summary = []
        for branch in pruned_branches:
            evaluation = branch.get("evaluation", {})
            pruned_summary.append({
                "branch_id": branch["branch_id"],
                "strategy": branch["strategy"],
                "quality_score": branch.get("quality_score"),
                "reason": f"Quality below threshold ({self.quality_threshold})",
            })

        return {
            "high_quality_branches": high_quality_summary,
            "pruned_branches": pruned_summary,
        }

    def _create_fair_adapter(self) -> object:
        """Create FAIR (Factor Analysis of Information Risk) adapter.

        Returns:
            FAIR adapter (simplified mock for now)
        """
        # Simplified FAIR adapter
        class FAIRAdapter:
            def assess_risk(self, cve, asset, context):
                # Simplified FAIR quantification
                score = 6.0

                if cve and "cvss_score" in cve:
                    cvss = float(cve["cvss_score"])
                    score = cvss

                return {
                    "framework": "FAIR",
                    "overall_score": score,
                    "risk_level": self._score_to_level(score),
                    "loss_magnitude": {"min": 10000, "max": 500000, "most_likely": 100000},
                    "threat_event_frequency": {"min": 0.1, "max": 5.0, "most_likely": 1.0},
                    "confidence": 0.75,
                }

            def _score_to_level(self, score):
                if score >= 8.0:
                    return "Critical"
                elif score >= 6.0:
                    return "High"
                elif score >= 4.0:
                    return "Medium"
                else:
                    return "Low"

        return FAIRAdapter()

    def _create_quantitative_adapter(self) -> object:
        """Create Quantitative risk analysis adapter.

        Returns:
            Quantitative adapter (simplified mock for now)
        """
        # Simplified quantitative adapter
        class QuantitativeAdapter:
            def assess_risk(self, cve, asset, context):
                # Simplified quantitative analysis
                score = 5.0

                if cve and "cvss_score" in cve:
                    cvss = float(cve["cvss_score"])
                    score = cvss * 0.9  # Slight variation

                return {
                    "framework": "Quantitative",
                    "overall_score": score,
                    "risk_level": self._score_to_level(score),
                    "probability": 0.3,
                    "impact": 7.5,
                    "expected_loss": 225000,
                    "confidence": 0.70,
                }

            def _score_to_level(self, score):
                if score >= 8.0:
                    return "Critical"
                elif score >= 6.0:
                    return "High"
                elif score >= 4.0:
                    return "Medium"
                else:
                    return "Low"

        return QuantitativeAdapter()

    def _score_to_risk_level(self, score: float) -> str:
        """Convert numeric score to risk level.

        Args:
            score: Risk score (0-10)

        Returns:
            Risk level string
        """
        if score >= 8.0:
            return "Critical"
        elif score >= 6.0:
            return "High"
        elif score >= 4.0:
            return "Medium"
        else:
            return "Low"
