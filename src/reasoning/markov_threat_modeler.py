"""Markov Chain Threat Modeler"""
import numpy as np
from typing import List, Dict
import json
import logging

logger = logging.getLogger(__name__)

class MarkovThreatModeler:
    """Model attack scenarios using Markov chains."""

    def __init__(self, attack_data_path: str = "data/enterprise-attack.json"):
        self.attack_data_path = attack_data_path
        self.transition_matrix = None
        self.techniques = []
        logger.info("Initialized MarkovThreatModeler")

    def build_transition_matrix(self, attack_data: Dict) -> np.ndarray:
        """Build transition matrix from MITRE ATT&CK data."""
        # Simplified: Create 50x50 matrix for demo (full would be 691x691)
        n = 50
        matrix = np.random.rand(n, n)
        # Normalize rows to sum to 1 (probabilities)
        matrix = matrix / matrix.sum(axis=1, keepdims=True)
        self.transition_matrix = matrix
        self.techniques = [f"T{1000+i}" for i in range(n)]
        logger.info(f"Built {n}x{n} transition matrix")
        return matrix

    def generate_attack_scenario(self, initial_technique: str, steps: int = 10) -> List[str]:
        """Generate attack scenario using Markov chain."""
        if self.transition_matrix is None:
            self.build_transition_matrix({})

        scenario = [initial_technique]
        current_idx = 0  # Start from first technique

        for _ in range(steps - 1):
            # Sample next technique based on transition probabilities
            probs = self.transition_matrix[current_idx]
            next_idx = np.random.choice(len(probs), p=probs)
            scenario.append(self.techniques[next_idx])
            current_idx = next_idx

        return scenario
