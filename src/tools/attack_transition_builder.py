"""Attack Transition Builder"""
from typing import Dict, List, Tuple
import json
import pickle
import logging

logger = logging.getLogger(__name__)

class AttackTransitionBuilder:
    """Build attack technique transition data."""

    def __init__(self):
        logger.info("Initialized AttackTransitionBuilder")

    def parse_attack_json(self, file_path: str) -> Dict:
        """Parse MITRE ATT&CK JSON."""
        try:
            with open(file_path, 'r') as f:
                return json.load(f)
        except FileNotFoundError:
            logger.warning(f"Attack data not found: {file_path}")
            return {}

    def extract_technique_relationships(self, attack_data: Dict) -> List[Tuple[str, str]]:
        """Extract technique relationships."""
        # Simplified extraction
        relationships = []
        # Mock relationships
        for i in range(100):
            relationships.append((f"T{1000+i}", f"T{1001+i}"))
        return relationships

    def calculate_probabilities(self, relationships: List[Tuple]) -> Dict:
        """Calculate transition probabilities."""
        prob_dict = {}
        for src, dst in relationships:
            if src not in prob_dict:
                prob_dict[src] = {}
            prob_dict[src][dst] = prob_dict[src].get(dst, 0) + 1
        return prob_dict

    def save_matrix(self, matrix, file_path: str):
        """Save transition matrix to pickle."""
        with open(file_path, 'wb') as f:
            pickle.dump(matrix, f)
        logger.info(f"Saved matrix to {file_path}")
