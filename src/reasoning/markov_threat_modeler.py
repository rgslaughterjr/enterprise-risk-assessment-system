"""Markov Chain Threat Modeler for attack scenario generation.

This module uses Markov chains to generate probabilistic attack scenarios
based on MITRE ATT&CK technique transition matrices.
"""

import logging
import random
from typing import List, Dict, Optional, Tuple, Set
from pathlib import Path
import numpy as np

from ..tools.attack_transition_builder import AttackTransitionBuilder

logger = logging.getLogger(__name__)


class AttackScenario:
    """Represents a generated attack scenario."""

    def __init__(
        self,
        techniques: List[str],
        probability: float,
        tactics: List[str],
        description: str = "",
    ):
        """Initialize attack scenario.

        Args:
            techniques: List of technique IDs in attack path
            probability: Probability of this scenario
            tactics: List of tactics corresponding to techniques
            description: Human-readable description
        """
        self.techniques = techniques
        self.probability = probability
        self.tactics = tactics
        self.description = description

    def __repr__(self) -> str:
        """String representation."""
        return (
            f"AttackScenario(techniques={len(self.techniques)}, "
            f"probability={self.probability:.4f})"
        )

    def to_dict(self) -> Dict:
        """Convert to dictionary."""
        return {
            "techniques": self.techniques,
            "probability": self.probability,
            "tactics": self.tactics,
            "description": self.description,
        }


class MarkovThreatModeler:
    """Markov chain-based threat modeling for attack scenario generation.

    This class uses transition probability matrices derived from MITRE ATT&CK
    to generate realistic attack scenarios using Markov chains.
    """

    def __init__(
        self,
        transition_builder: Optional[AttackTransitionBuilder] = None,
        cache_path: str = "data/attack_matrix.pkl",
    ):
        """Initialize Markov threat modeler.

        Args:
            transition_builder: Pre-built transition builder. If None, creates new one.
            cache_path: Path to cached transition matrix
        """
        self.cache_path = cache_path
        self.transition_builder = transition_builder

        if self.transition_builder is None:
            self.transition_builder = AttackTransitionBuilder()

            # Try to load cached matrix
            if not self.transition_builder.load_cached_matrix(cache_path):
                logger.info("Building new transition matrix")
                self._build_matrix()
                self.transition_builder.cache_matrix(cache_path)
        else:
            logger.info("Using provided transition builder")

        # Validate matrix exists
        if self.transition_builder.transition_matrix is None:
            logger.warning("No transition matrix available. Building from data.")
            self._build_matrix()

    def _build_matrix(self) -> None:
        """Build transition matrix from MITRE ATT&CK data."""
        self.transition_builder.parse_mitre_attack()
        self.transition_builder.extract_technique_relationships()
        self.transition_builder.calculate_transition_probabilities()
        self.transition_builder.build_transition_matrix()

        logger.info("Transition matrix built successfully")

    def build_transition_matrix(self) -> np.ndarray:
        """Build and return transition matrix.

        Returns:
            NxN transition matrix where N = number of techniques
        """
        if self.transition_builder.transition_matrix is not None:
            return self.transition_builder.transition_matrix

        self._build_matrix()
        return self.transition_builder.transition_matrix

    def generate_scenario(
        self,
        initial_technique: str,
        steps: int = 10,
        min_probability: float = 0.01,
    ) -> AttackScenario:
        """Generate attack scenario starting from initial technique.

        Uses Markov chain to randomly walk through techniques based on
        transition probabilities.

        Args:
            initial_technique: Starting technique ID (e.g., "T1190")
            steps: Maximum number of steps in scenario
            min_probability: Minimum transition probability to consider

        Returns:
            AttackScenario object
        """
        if initial_technique not in self.transition_builder.technique_index:
            logger.warning(f"Technique {initial_technique} not found in matrix")
            # Return empty scenario
            return AttackScenario(
                techniques=[initial_technique],
                probability=0.0,
                tactics=[],
                description=f"Invalid initial technique: {initial_technique}",
            )

        techniques = [initial_technique]
        current_technique = initial_technique
        scenario_probability = 1.0
        visited = {initial_technique}

        for step in range(steps - 1):
            # Get possible next techniques
            next_techniques = self._get_next_techniques(
                current_technique, min_probability, visited
            )

            if not next_techniques:
                logger.debug(f"No more transitions from {current_technique}")
                break

            # Select next technique based on probabilities
            next_tech, transition_prob = self._sample_next_technique(next_techniques)

            techniques.append(next_tech)
            scenario_probability *= transition_prob
            visited.add(next_tech)
            current_technique = next_tech

        # Build tactics list
        tactics = self._get_tactics_for_techniques(techniques)

        # Generate description
        description = self._generate_scenario_description(techniques, tactics)

        return AttackScenario(
            techniques=techniques,
            probability=scenario_probability,
            tactics=tactics,
            description=description,
        )

    def _get_next_techniques(
        self,
        current_technique: str,
        min_probability: float,
        visited: Set[str],
    ) -> List[Tuple[str, float]]:
        """Get possible next techniques from current technique.

        Args:
            current_technique: Current technique ID
            min_probability: Minimum probability threshold
            visited: Set of already visited techniques

        Returns:
            List of (technique_id, probability) tuples
        """
        if current_technique not in self.transition_builder.transition_probs:
            return []

        next_techniques = []
        transitions = self.transition_builder.transition_probs[current_technique]

        for tech_id, prob in transitions.items():
            # Filter by minimum probability and avoid cycles (optional)
            if prob >= min_probability:
                # Penalize revisiting techniques but don't exclude entirely
                if tech_id in visited:
                    prob *= 0.3
                next_techniques.append((tech_id, prob))

        # Sort by probability (descending)
        next_techniques.sort(key=lambda x: x[1], reverse=True)

        return next_techniques

    def _sample_next_technique(
        self, next_techniques: List[Tuple[str, float]]
    ) -> Tuple[str, float]:
        """Sample next technique from probability distribution.

        Args:
            next_techniques: List of (technique_id, probability) tuples

        Returns:
            (selected_technique_id, probability)
        """
        if not next_techniques:
            return ("", 0.0)

        # Normalize probabilities
        total_prob = sum(prob for _, prob in next_techniques)
        normalized = [(tech, prob / total_prob) for tech, prob in next_techniques]

        # Sample based on probabilities
        rand_val = random.random()
        cumulative = 0.0

        for tech_id, prob in normalized:
            cumulative += prob
            if rand_val <= cumulative:
                return (tech_id, prob)

        # Fallback to highest probability
        return normalized[0]

    def _get_tactics_for_techniques(self, techniques: List[str]) -> List[str]:
        """Get primary tactics for each technique.

        Args:
            techniques: List of technique IDs

        Returns:
            List of tactic names
        """
        tactics = []

        for tech_id in techniques:
            tech_data = self.transition_builder.techniques.get(tech_id, {})
            tech_tactics = tech_data.get("tactics", [])

            if tech_tactics:
                tactics.append(tech_tactics[0])  # Use primary tactic
            else:
                tactics.append("unknown")

        return tactics

    def _generate_scenario_description(
        self, techniques: List[str], tactics: List[str]
    ) -> str:
        """Generate human-readable scenario description.

        Args:
            techniques: List of technique IDs
            tactics: List of tactics

        Returns:
            Description string
        """
        if not techniques:
            return "Empty attack scenario"

        parts = []
        parts.append(f"Attack scenario with {len(techniques)} steps:\n")

        for i, (tech_id, tactic) in enumerate(zip(techniques, tactics), 1):
            tech_name = self.transition_builder.get_technique_name(tech_id)
            parts.append(f"{i}. {tech_id} - {tech_name} [{tactic}]")

        return "\n".join(parts)

    def calculate_probability(self, path: List[str]) -> float:
        """Calculate probability of a specific attack path.

        Args:
            path: List of technique IDs representing attack path

        Returns:
            Probability of the path (0.0 to 1.0)
        """
        if len(path) < 2:
            return 1.0  # Single technique has probability 1.0

        probability = 1.0

        for i in range(len(path) - 1):
            src_tech = path[i]
            dst_tech = path[i + 1]

            # Get transition probability
            if src_tech in self.transition_builder.transition_probs:
                transition_prob = self.transition_builder.transition_probs[src_tech].get(
                    dst_tech, 0.0
                )
                probability *= transition_prob
            else:
                # No known transition
                return 0.0

        return probability

    def generate_monte_carlo_scenarios(
        self,
        initial_technique: str,
        num_scenarios: int = 100,
        steps: int = 10,
        min_probability: float = 0.01,
    ) -> List[AttackScenario]:
        """Generate multiple scenarios using Monte Carlo sampling.

        Args:
            initial_technique: Starting technique ID
            num_scenarios: Number of scenarios to generate
            steps: Maximum steps per scenario
            min_probability: Minimum transition probability

        Returns:
            List of AttackScenario objects, sorted by probability
        """
        scenarios = []

        for _ in range(num_scenarios):
            scenario = self.generate_scenario(
                initial_technique, steps, min_probability
            )
            scenarios.append(scenario)

        # Remove duplicates (same technique sequence)
        unique_scenarios = self._deduplicate_scenarios(scenarios)

        # Sort by probability (descending)
        unique_scenarios.sort(key=lambda s: s.probability, reverse=True)

        logger.info(
            f"Generated {len(unique_scenarios)} unique scenarios from {num_scenarios} samples"
        )

        return unique_scenarios

    def _deduplicate_scenarios(
        self, scenarios: List[AttackScenario]
    ) -> List[AttackScenario]:
        """Remove duplicate scenarios.

        Args:
            scenarios: List of scenarios

        Returns:
            List of unique scenarios
        """
        seen = {}

        for scenario in scenarios:
            # Use technique sequence as key
            key = tuple(scenario.techniques)

            if key not in seen or scenario.probability > seen[key].probability:
                seen[key] = scenario

        return list(seen.values())

    def find_most_likely_path(
        self,
        start_technique: str,
        end_technique: str,
        max_depth: int = 10,
    ) -> Optional[AttackScenario]:
        """Find most likely path between two techniques using dynamic programming.

        Args:
            start_technique: Starting technique ID
            end_technique: Target technique ID
            max_depth: Maximum path length

        Returns:
            Most likely AttackScenario or None if no path found
        """
        if start_technique not in self.transition_builder.technique_index:
            logger.warning(f"Start technique {start_technique} not found")
            return None

        if end_technique not in self.transition_builder.technique_index:
            logger.warning(f"End technique {end_technique} not found")
            return None

        # Use Dijkstra-like algorithm with probabilities
        # State: (technique, path, probability)
        queue = [(start_technique, [start_technique], 1.0)]
        best_paths = {start_technique: (1.0, [start_technique])}

        while queue:
            current_tech, path, prob = queue.pop(0)

            # Check if reached target
            if current_tech == end_technique:
                tactics = self._get_tactics_for_techniques(path)
                description = self._generate_scenario_description(path, tactics)

                return AttackScenario(
                    techniques=path,
                    probability=prob,
                    tactics=tactics,
                    description=description,
                )

            # Check depth limit
            if len(path) >= max_depth:
                continue

            # Explore neighbors
            if current_tech not in self.transition_builder.transition_probs:
                continue

            for next_tech, transition_prob in self.transition_builder.transition_probs[
                current_tech
            ].items():
                new_prob = prob * transition_prob
                new_path = path + [next_tech]

                # Update if better path found
                if next_tech not in best_paths or new_prob > best_paths[next_tech][0]:
                    best_paths[next_tech] = (new_prob, new_path)
                    queue.append((next_tech, new_path, new_prob))

        logger.warning(f"No path found from {start_technique} to {end_technique}")
        return None

    def get_top_next_techniques(
        self, current_technique: str, top_k: int = 5
    ) -> List[Tuple[str, float, str]]:
        """Get top K most likely next techniques.

        Args:
            current_technique: Current technique ID
            top_k: Number of top techniques to return

        Returns:
            List of (technique_id, probability, technique_name) tuples
        """
        if current_technique not in self.transition_builder.transition_probs:
            return []

        transitions = self.transition_builder.transition_probs[current_technique]

        # Sort by probability
        sorted_transitions = sorted(
            transitions.items(), key=lambda x: x[1], reverse=True
        )

        # Get top K
        top_transitions = sorted_transitions[:top_k]

        # Add technique names
        result = []
        for tech_id, prob in top_transitions:
            tech_name = self.transition_builder.get_technique_name(tech_id)
            result.append((tech_id, prob, tech_name))

        return result

    def analyze_technique_reachability(
        self, technique: str, max_steps: int = 5
    ) -> Dict[str, float]:
        """Analyze which techniques are reachable from given technique.

        Args:
            technique: Starting technique ID
            max_steps: Maximum number of steps to explore

        Returns:
            Dictionary mapping reachable technique IDs to probabilities
        """
        if technique not in self.transition_builder.technique_index:
            return {}

        reachable = {technique: 1.0}
        current_layer = {technique: 1.0}

        for step in range(max_steps):
            next_layer = {}

            for current_tech, current_prob in current_layer.items():
                if current_tech not in self.transition_builder.transition_probs:
                    continue

                for next_tech, transition_prob in self.transition_builder.transition_probs[
                    current_tech
                ].items():
                    new_prob = current_prob * transition_prob

                    # Update if better probability found
                    if next_tech not in reachable or new_prob > reachable[next_tech]:
                        reachable[next_tech] = new_prob
                        next_layer[next_tech] = new_prob

            if not next_layer:
                break

            current_layer = next_layer

        return reachable

    def get_statistics(self) -> Dict[str, any]:
        """Get statistics about the threat modeler.

        Returns:
            Dictionary with statistics
        """
        matrix_stats = self.transition_builder.get_statistics()

        # Calculate additional stats
        if self.transition_builder.transition_matrix is not None:
            matrix = self.transition_builder.transition_matrix
            non_zero = np.count_nonzero(matrix)
            sparsity = 1.0 - (non_zero / matrix.size)

            matrix_stats.update({
                "matrix_non_zero": int(non_zero),
                "matrix_sparsity": float(sparsity),
                "matrix_shape": matrix.shape,
            })

        return matrix_stats
