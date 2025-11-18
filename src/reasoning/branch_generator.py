"""Branch Generator for Tree of Thought (ToT) risk assessment.

This module generates multiple parallel evaluation branches for each risk,
using different assessment strategies and frameworks to enable multi-perspective
risk analysis and consensus scoring.
"""

import logging
from typing import List, Dict, Any, Optional
from datetime import datetime
from enum import Enum
import random

logger = logging.getLogger(__name__)


class EvaluationStrategy(Enum):
    """Supported risk evaluation strategies."""
    NIST_AI_RMF = "nist_ai_rmf"
    OCTAVE = "octave"
    ISO_31000 = "iso31000"
    FAIR = "fair"
    QUANTITATIVE = "quantitative"


class BranchGenerator:
    """Generates multiple evaluation branches using different strategies.

    Implements Tree of Thought approach where each risk is evaluated through
    multiple parallel reasoning paths using different frameworks and methodologies.
    """

    def __init__(
        self,
        default_strategies: Optional[List[str]] = None,
        enable_randomization: bool = False,
    ):
        """Initialize branch generator.

        Args:
            default_strategies: List of strategy names to use (default: all)
            enable_randomization: If True, add randomization to branch parameters
        """
        if default_strategies is None:
            default_strategies = [s.value for s in EvaluationStrategy]

        self.default_strategies = default_strategies
        self.enable_randomization = enable_randomization

        logger.info(f"Branch generator initialized with {len(default_strategies)} strategies")

    def generate_branches(
        self,
        risk: Dict[str, Any],
        strategies: Optional[List[str]] = None,
        num_branches: int = 5,
    ) -> List[Dict[str, Any]]:
        """Generate multiple evaluation branches for a risk.

        Args:
            risk: Risk dictionary with id, title, description, etc.
            strategies: List of strategy names (uses default if None)
            num_branches: Number of branches to generate (default: 5)

        Returns:
            List of branch dictionaries with strategy and evaluation parameters

        Example:
            >>> generator = BranchGenerator()
            >>> risk = {"id": "RISK-001", "title": "SQL Injection"}
            >>> branches = generator.generate_branches(risk, num_branches=5)
            >>> len(branches)
            5
        """
        if strategies is None:
            strategies = self.default_strategies

        if num_branches > len(strategies):
            # Duplicate strategies to reach target number
            strategies = self._expand_strategies(strategies, num_branches)
        elif num_branches < len(strategies):
            # Select subset of strategies
            strategies = strategies[:num_branches]

        logger.info(f"Generating {num_branches} branches for risk {risk.get('id')}")

        branches = []
        for i, strategy in enumerate(strategies):
            branch = self._create_branch(risk, strategy, i)
            branches.append(branch)

        logger.info(f"Generated {len(branches)} evaluation branches")
        return branches

    def _create_branch(
        self,
        risk: Dict[str, Any],
        strategy: str,
        branch_index: int,
    ) -> Dict[str, Any]:
        """Create a single evaluation branch.

        Args:
            risk: Risk dictionary
            strategy: Strategy name
            branch_index: Index of this branch

        Returns:
            Branch dictionary with strategy and parameters
        """
        branch = {
            "branch_id": f"{risk.get('id', 'UNKNOWN')}_{strategy}_{branch_index}",
            "risk_id": risk.get("id", "UNKNOWN"),
            "risk_title": risk.get("title", ""),
            "risk_description": risk.get("description", ""),
            "strategy": strategy,
            "branch_index": branch_index,
            "created_at": datetime.utcnow().isoformat(),
            "parameters": self._generate_parameters(strategy, risk),
            "status": "pending",
            "evaluation": None,
            "quality_score": None,
        }

        return branch

    def _generate_parameters(
        self,
        strategy: str,
        risk: Dict[str, Any],
    ) -> Dict[str, Any]:
        """Generate strategy-specific evaluation parameters.

        Args:
            strategy: Strategy name
            risk: Risk dictionary

        Returns:
            Parameters dictionary for the strategy
        """
        base_params = {
            "risk_level": risk.get("risk_level", "Medium"),
            "cve_ids": risk.get("cve_ids", []),
            "affected_assets": risk.get("affected_assets", []),
        }

        # Strategy-specific parameters
        if strategy == EvaluationStrategy.NIST_AI_RMF.value:
            params = {
                **base_params,
                "functions": ["GOVERN", "MAP", "MEASURE", "MANAGE"],
                "consider_ai_context": True,
                "ai_system_category": risk.get("ai_system_category", "general"),
            }

        elif strategy == EvaluationStrategy.OCTAVE.value:
            params = {
                **base_params,
                "phases": ["establish_drivers", "profile_assets", "identify_threats"],
                "organizational_impact": True,
                "asset_criticality": risk.get("asset_criticality", "medium"),
            }

        elif strategy == EvaluationStrategy.ISO_31000.value:
            params = {
                **base_params,
                "likelihood_scale": 5,
                "consequence_scale": 5,
                "risk_matrix": "5x5",
                "include_residual_risk": True,
            }

        elif strategy == EvaluationStrategy.FAIR.value:
            params = {
                **base_params,
                "loss_magnitude": True,
                "threat_event_frequency": True,
                "vulnerability_assessment": True,
                "quantify_financial_impact": True,
            }

        elif strategy == EvaluationStrategy.QUANTITATIVE.value:
            params = {
                **base_params,
                "use_monte_carlo": False,  # Simplified for now
                "probability_distribution": "uniform",
                "impact_range": (0, 100),
            }

        else:
            params = base_params

        # Add randomization if enabled
        if self.enable_randomization:
            params["random_seed"] = random.randint(1000, 9999)
            params["sampling_variance"] = random.uniform(0.05, 0.15)

        return params

    def _expand_strategies(
        self,
        strategies: List[str],
        target_count: int,
    ) -> List[str]:
        """Expand strategy list to reach target count.

        Args:
            strategies: Original strategy list
            target_count: Desired number of strategies

        Returns:
            Expanded strategy list
        """
        expanded = strategies.copy()

        while len(expanded) < target_count:
            # Add strategies in round-robin fashion
            for strategy in strategies:
                if len(expanded) >= target_count:
                    break
                expanded.append(strategy)

        return expanded

    def generate_comparative_branches(
        self,
        risk: Dict[str, Any],
        baseline_score: Optional[float] = None,
    ) -> List[Dict[str, Any]]:
        """Generate branches with baseline comparison capability.

        Args:
            risk: Risk dictionary
            baseline_score: Optional baseline score for comparison

        Returns:
            List of branches with baseline comparison metadata
        """
        branches = self.generate_branches(risk)

        for branch in branches:
            branch["baseline_score"] = baseline_score
            branch["comparison_enabled"] = baseline_score is not None

        return branches

    def generate_weighted_branches(
        self,
        risk: Dict[str, Any],
        strategy_weights: Optional[Dict[str, float]] = None,
    ) -> List[Dict[str, Any]]:
        """Generate branches with predefined strategy weights.

        Args:
            risk: Risk dictionary
            strategy_weights: Dictionary mapping strategy names to weights

        Returns:
            List of branches with weight metadata
        """
        if strategy_weights is None:
            # Default equal weights
            strategy_weights = {s: 1.0 / len(self.default_strategies) for s in self.default_strategies}

        # Normalize weights
        total_weight = sum(strategy_weights.values())
        normalized_weights = {k: v / total_weight for k, v in strategy_weights.items()}

        branches = self.generate_branches(
            risk,
            strategies=list(strategy_weights.keys()),
            num_branches=len(strategy_weights)
        )

        for branch in branches:
            strategy = branch["strategy"]
            branch["weight"] = normalized_weights.get(strategy, 0.0)

        return branches

    def get_strategy_info(self, strategy: str) -> Dict[str, Any]:
        """Get information about a specific strategy.

        Args:
            strategy: Strategy name

        Returns:
            Strategy information dictionary
        """
        strategy_info = {
            EvaluationStrategy.NIST_AI_RMF.value: {
                "name": "NIST AI Risk Management Framework",
                "version": "1.0",
                "focus": "AI-specific risks and governance",
                "functions": 4,
                "best_for": "AI/ML systems and algorithms",
            },
            EvaluationStrategy.OCTAVE.value: {
                "name": "OCTAVE Allegro",
                "version": "Allegro",
                "focus": "Organizational operational risks",
                "phases": 3,
                "best_for": "Enterprise-wide risk assessment",
            },
            EvaluationStrategy.ISO_31000.value: {
                "name": "ISO 31000:2018",
                "version": "2018",
                "focus": "General risk management",
                "matrix": "5x5 likelihood/consequence",
                "best_for": "Broad risk management frameworks",
            },
            EvaluationStrategy.FAIR.value: {
                "name": "Factor Analysis of Information Risk",
                "version": "FAIR",
                "focus": "Quantitative cyber risk",
                "approach": "Financial impact quantification",
                "best_for": "Financial risk quantification",
            },
            EvaluationStrategy.QUANTITATIVE.value: {
                "name": "Quantitative Risk Analysis",
                "version": "Generic",
                "focus": "Numerical probability and impact",
                "approach": "Statistical modeling",
                "best_for": "Data-driven risk assessment",
            },
        }

        return strategy_info.get(strategy, {"name": "Unknown", "version": "N/A"})

    def get_supported_strategies(self) -> List[str]:
        """Get list of all supported strategies.

        Returns:
            List of strategy names
        """
        return [s.value for s in EvaluationStrategy]
