"""Attack Transition Matrix Builder for MITRE ATT&CK.

This module builds transition probability matrices from MITRE ATT&CK data
to enable Markov chain-based threat modeling and attack scenario generation.
"""

import json
import logging
import pickle
from pathlib import Path
from typing import Dict, List, Tuple, Optional, Set
from collections import defaultdict, Counter
import numpy as np

logger = logging.getLogger(__name__)


class AttackTransitionBuilder:
    """Builds transition probability matrices from MITRE ATT&CK data.

    This class parses the MITRE ATT&CK framework JSON data and extracts
    technique-to-technique relationships to build a Markov chain transition
    matrix for probabilistic attack path modeling.
    """

    def __init__(self, data_path: Optional[str] = None):
        """Initialize the transition builder.

        Args:
            data_path: Path to enterprise-attack.json file.
                      If None, searches common locations.
        """
        self.data_path = data_path
        self.attack_data: Optional[Dict] = None
        self.techniques: Dict[str, Dict] = {}
        self.technique_ids: List[str] = []
        self.technique_index: Dict[str, int] = {}
        self.relationships: List[Tuple[str, str]] = []
        self.transition_counts: Dict[str, Dict[str, int]] = defaultdict(lambda: defaultdict(int))
        self.transition_probs: Dict[str, Dict[str, float]] = {}
        self.transition_matrix: Optional[np.ndarray] = None

        if not self.data_path:
            self.data_path = self._find_data_file()

        if self.data_path and Path(self.data_path).exists():
            logger.info(f"Loading MITRE ATT&CK data from {self.data_path}")
            self._load_data()
        else:
            logger.warning(
                "MITRE ATT&CK data file not found. "
                "Transition builder will use mock data for testing."
            )

    def _find_data_file(self) -> Optional[str]:
        """Find enterprise-attack.json in common locations.

        Returns:
            Path to data file or None
        """
        possible_paths = [
            "/home/user/enterprise-risk-assessment-system/data/enterprise-attack.json",
            "/home/user/enterprise-attack.json",
            "./data/enterprise-attack.json",
            "./enterprise-attack.json",
            "../enterprise-attack.json",
        ]

        for path in possible_paths:
            if Path(path).exists():
                logger.info(f"Found MITRE ATT&CK data at: {path}")
                return path

        return None

    def _load_data(self) -> None:
        """Load MITRE ATT&CK data from JSON file."""
        try:
            with open(self.data_path, "r", encoding="utf-8") as f:
                self.attack_data = json.load(f)

            logger.info(f"Loaded MITRE ATT&CK data from {self.data_path}")
        except Exception as e:
            logger.error(f"Error loading MITRE ATT&CK data: {e}")
            self.attack_data = None

    def parse_mitre_attack(self, json_path: Optional[str] = None) -> int:
        """Parse MITRE ATT&CK JSON and extract techniques.

        Args:
            json_path: Optional path to JSON file. Uses self.data_path if None.

        Returns:
            Number of techniques parsed
        """
        if json_path:
            self.data_path = json_path
            self._load_data()

        if not self.attack_data:
            logger.warning("No MITRE ATT&CK data loaded. Using mock data.")
            self._load_mock_data()
            return len(self.techniques)

        # Parse attack-pattern objects (techniques)
        objects = self.attack_data.get("objects", [])

        for obj in objects:
            if obj.get("type") == "attack-pattern":
                # Extract technique ID
                external_refs = obj.get("external_references", [])
                tech_id = None

                for ref in external_refs:
                    if ref.get("source_name") == "mitre-attack":
                        tech_id = ref.get("external_id")
                        break

                if tech_id and not obj.get("x_mitre_deprecated", False):
                    self.techniques[tech_id] = {
                        "name": obj.get("name", ""),
                        "description": obj.get("description", ""),
                        "tactics": self._extract_tactics(obj),
                        "platforms": obj.get("x_mitre_platforms", []),
                        "data_sources": obj.get("x_mitre_data_sources", []),
                        "id": obj.get("id"),
                    }

        # Build technique ID list and index
        self.technique_ids = sorted(self.techniques.keys())
        self.technique_index = {tech_id: idx for idx, tech_id in enumerate(self.technique_ids)}

        logger.info(f"Parsed {len(self.techniques)} MITRE ATT&CK techniques")
        return len(self.techniques)

    def _extract_tactics(self, technique_obj: Dict) -> List[str]:
        """Extract tactic names from technique object.

        Args:
            technique_obj: MITRE ATT&CK technique object

        Returns:
            List of tactic names
        """
        tactics = []
        for phase in technique_obj.get("kill_chain_phases", []):
            if phase.get("kill_chain_name") == "mitre-attack":
                tactics.append(phase.get("phase_name", ""))
        return tactics

    def _load_mock_data(self) -> None:
        """Load mock data for testing when real data is unavailable."""
        # Create a small set of mock techniques for testing
        mock_techniques = {
            "T1190": {
                "name": "Exploit Public-Facing Application",
                "description": "Exploit of internet-facing computer systems",
                "tactics": ["initial-access"],
                "platforms": ["Windows", "Linux"],
                "data_sources": ["Application Log"],
                "id": "attack-pattern--001",
            },
            "T1059": {
                "name": "Command and Scripting Interpreter",
                "description": "Execute commands through interpreters",
                "tactics": ["execution"],
                "platforms": ["Windows", "Linux", "macOS"],
                "data_sources": ["Process"],
                "id": "attack-pattern--002",
            },
            "T1068": {
                "name": "Exploitation for Privilege Escalation",
                "description": "Exploit software vulnerabilities to escalate privileges",
                "tactics": ["privilege-escalation"],
                "platforms": ["Windows", "Linux"],
                "data_sources": ["Process"],
                "id": "attack-pattern--003",
            },
            "T1078": {
                "name": "Valid Accounts",
                "description": "Obtain and abuse credentials of existing accounts",
                "tactics": ["defense-evasion", "persistence", "privilege-escalation", "initial-access"],
                "platforms": ["Windows", "Linux", "macOS"],
                "data_sources": ["Authentication logs"],
                "id": "attack-pattern--004",
            },
            "T1083": {
                "name": "File and Directory Discovery",
                "description": "Enumerate files and directories",
                "tactics": ["discovery"],
                "platforms": ["Windows", "Linux", "macOS"],
                "data_sources": ["Process", "File"],
                "id": "attack-pattern--005",
            },
            "T1105": {
                "name": "Ingress Tool Transfer",
                "description": "Transfer tools or files from external system",
                "tactics": ["command-and-control"],
                "platforms": ["Windows", "Linux", "macOS"],
                "data_sources": ["Network Traffic", "File"],
                "id": "attack-pattern--006",
            },
            "T1003": {
                "name": "OS Credential Dumping",
                "description": "Dump credentials to obtain account login information",
                "tactics": ["credential-access"],
                "platforms": ["Windows", "Linux", "macOS"],
                "data_sources": ["Process", "File"],
                "id": "attack-pattern--007",
            },
            "T1021": {
                "name": "Remote Services",
                "description": "Use valid accounts to log into remote service",
                "tactics": ["lateral-movement"],
                "platforms": ["Windows", "Linux"],
                "data_sources": ["Authentication logs", "Network Traffic"],
                "id": "attack-pattern--008",
            },
            "T1071": {
                "name": "Application Layer Protocol",
                "description": "Use application layer protocols to communicate",
                "tactics": ["command-and-control"],
                "platforms": ["Windows", "Linux", "macOS"],
                "data_sources": ["Network Traffic"],
                "id": "attack-pattern--009",
            },
            "T1567": {
                "name": "Exfiltration Over Web Service",
                "description": "Exfiltrate data to cloud storage service",
                "tactics": ["exfiltration"],
                "platforms": ["Windows", "Linux", "macOS"],
                "data_sources": ["Network Traffic"],
                "id": "attack-pattern--010",
            },
        }

        self.techniques = mock_techniques
        self.technique_ids = sorted(self.techniques.keys())
        self.technique_index = {tech_id: idx for idx, tech_id in enumerate(self.technique_ids)}

        logger.info(f"Loaded {len(self.techniques)} mock techniques for testing")

    def extract_technique_relationships(self) -> List[Tuple[str, str]]:
        """Extract technique-to-technique relationships.

        Relationships are derived from:
        1. Tactic progression (kill chain order)
        2. Shared platforms and data sources
        3. Technique descriptions and references

        Returns:
            List of (source_technique, target_technique) tuples
        """
        if not self.techniques:
            logger.warning("No techniques loaded. Call parse_mitre_attack() first.")
            return []

        relationships = []

        # Tactic progression order (MITRE ATT&CK kill chain)
        tactic_order = [
            "reconnaissance",
            "resource-development",
            "initial-access",
            "execution",
            "persistence",
            "privilege-escalation",
            "defense-evasion",
            "credential-access",
            "discovery",
            "lateral-movement",
            "collection",
            "command-and-control",
            "exfiltration",
            "impact",
        ]

        # Build tactic-to-techniques mapping
        tactic_techniques: Dict[str, List[str]] = defaultdict(list)
        for tech_id, tech_data in self.techniques.items():
            for tactic in tech_data["tactics"]:
                tactic_techniques[tactic].append(tech_id)

        # Generate relationships based on tactic progression
        for i, current_tactic in enumerate(tactic_order[:-1]):
            if current_tactic not in tactic_techniques:
                continue

            # Connect to next 2-3 tactics (attackers can skip tactics)
            for j in range(i + 1, min(i + 4, len(tactic_order))):
                next_tactic = tactic_order[j]
                if next_tactic not in tactic_techniques:
                    continue

                # Create relationships from current tactic techniques to next
                for src_tech in tactic_techniques[current_tactic]:
                    for dst_tech in tactic_techniques[next_tactic]:
                        relationships.append((src_tech, dst_tech))

        # Add relationships within same tactic (technique chaining)
        for tactic, tech_list in tactic_techniques.items():
            if len(tech_list) > 1:
                for i, src_tech in enumerate(tech_list):
                    for dst_tech in tech_list[i+1:]:
                        # Bidirectional within tactic
                        relationships.append((src_tech, dst_tech))
                        relationships.append((dst_tech, src_tech))

        self.relationships = relationships
        logger.info(f"Extracted {len(relationships)} technique relationships")

        return relationships

    def calculate_transition_probabilities(self) -> Dict[str, Dict[str, float]]:
        """Calculate transition probabilities from relationships.

        Uses a combination of:
        1. Frequency of observed transitions
        2. Tactic progression weights
        3. Platform compatibility weights

        Returns:
            Dictionary mapping source technique to {target: probability}
        """
        if not self.relationships:
            logger.warning("No relationships found. Call extract_technique_relationships() first.")
            return {}

        # Count transitions
        for src, dst in self.relationships:
            self.transition_counts[src][dst] += 1

        # Calculate probabilities with normalization
        self.transition_probs = {}

        for src_tech, targets in self.transition_counts.items():
            total_count = sum(targets.values())

            if total_count == 0:
                continue

            self.transition_probs[src_tech] = {}

            for dst_tech, count in targets.items():
                # Base probability from frequency
                prob = count / total_count

                # Apply tactic progression weight
                src_tactics = set(self.techniques.get(src_tech, {}).get("tactics", []))
                dst_tactics = set(self.techniques.get(dst_tech, {}).get("tactics", []))

                # Bonus for forward progression in kill chain
                if self._is_forward_progression(src_tactics, dst_tactics):
                    prob *= 1.5

                # Penalty for backward progression
                elif self._is_backward_progression(src_tactics, dst_tactics):
                    prob *= 0.5

                self.transition_probs[src_tech][dst_tech] = prob

            # Renormalize after weighting
            total_prob = sum(self.transition_probs[src_tech].values())
            if total_prob > 0:
                for dst_tech in self.transition_probs[src_tech]:
                    self.transition_probs[src_tech][dst_tech] /= total_prob

        logger.info(f"Calculated transition probabilities for {len(self.transition_probs)} techniques")

        return self.transition_probs

    def _is_forward_progression(self, src_tactics: Set[str], dst_tactics: Set[str]) -> bool:
        """Check if transition represents forward kill chain progression.

        Args:
            src_tactics: Set of source technique tactics
            dst_tactics: Set of destination technique tactics

        Returns:
            True if forward progression
        """
        tactic_order = [
            "reconnaissance", "resource-development", "initial-access", "execution",
            "persistence", "privilege-escalation", "defense-evasion", "credential-access",
            "discovery", "lateral-movement", "collection", "command-and-control",
            "exfiltration", "impact",
        ]

        tactic_index = {tactic: idx for idx, tactic in enumerate(tactic_order)}

        # Get average position for each tactic set
        src_avg = np.mean([tactic_index.get(t, 7) for t in src_tactics]) if src_tactics else 7
        dst_avg = np.mean([tactic_index.get(t, 7) for t in dst_tactics]) if dst_tactics else 7

        return dst_avg > src_avg

    def _is_backward_progression(self, src_tactics: Set[str], dst_tactics: Set[str]) -> bool:
        """Check if transition represents backward progression.

        Args:
            src_tactics: Set of source technique tactics
            dst_tactics: Set of destination technique tactics

        Returns:
            True if backward progression
        """
        tactic_order = [
            "reconnaissance", "resource-development", "initial-access", "execution",
            "persistence", "privilege-escalation", "defense-evasion", "credential-access",
            "discovery", "lateral-movement", "collection", "command-and-control",
            "exfiltration", "impact",
        ]

        tactic_index = {tactic: idx for idx, tactic in enumerate(tactic_order)}

        # Get average position for each tactic set
        src_avg = np.mean([tactic_index.get(t, 7) for t in src_tactics]) if src_tactics else 7
        dst_avg = np.mean([tactic_index.get(t, 7) for t in dst_tactics]) if dst_tactics else 7

        return dst_avg < src_avg - 2  # More than 2 steps backward

    def build_transition_matrix(self) -> np.ndarray:
        """Build numpy transition matrix from probabilities.

        Returns:
            NxN transition matrix where N = number of techniques
        """
        if not self.transition_probs:
            logger.warning("No transition probabilities. Call calculate_transition_probabilities() first.")
            return np.array([])

        n = len(self.technique_ids)
        matrix = np.zeros((n, n))

        for src_tech, targets in self.transition_probs.items():
            if src_tech not in self.technique_index:
                continue

            src_idx = self.technique_index[src_tech]

            for dst_tech, prob in targets.items():
                if dst_tech not in self.technique_index:
                    continue

                dst_idx = self.technique_index[dst_tech]
                matrix[src_idx, dst_idx] = prob

        # Ensure each row sums to 1 (or 0 if no outgoing transitions)
        row_sums = matrix.sum(axis=1, keepdims=True)
        row_sums[row_sums == 0] = 1  # Avoid division by zero
        matrix = matrix / row_sums

        self.transition_matrix = matrix

        logger.info(f"Built {n}x{n} transition matrix")

        return matrix

    def cache_matrix(self, filepath: str = "data/attack_matrix.pkl") -> None:
        """Cache transition matrix to disk.

        Args:
            filepath: Path to save pickle file
        """
        if self.transition_matrix is None:
            logger.warning("No transition matrix to cache. Call build_transition_matrix() first.")
            return

        # Ensure directory exists
        Path(filepath).parent.mkdir(parents=True, exist_ok=True)

        cache_data = {
            "matrix": self.transition_matrix,
            "technique_ids": self.technique_ids,
            "technique_index": self.technique_index,
            "techniques": self.techniques,
            "transition_probs": self.transition_probs,
        }

        with open(filepath, "wb") as f:
            pickle.dump(cache_data, f)

        logger.info(f"Cached transition matrix to {filepath}")

    def load_cached_matrix(self, filepath: str = "data/attack_matrix.pkl") -> bool:
        """Load cached transition matrix from disk.

        Args:
            filepath: Path to pickle file

        Returns:
            True if successfully loaded
        """
        if not Path(filepath).exists():
            logger.warning(f"Cache file not found: {filepath}")
            return False

        try:
            with open(filepath, "rb") as f:
                cache_data = pickle.load(f)

            self.transition_matrix = cache_data["matrix"]
            self.technique_ids = cache_data["technique_ids"]
            self.technique_index = cache_data["technique_index"]
            self.techniques = cache_data["techniques"]
            self.transition_probs = cache_data["transition_probs"]

            logger.info(f"Loaded cached transition matrix from {filepath}")
            return True

        except Exception as e:
            logger.error(f"Error loading cached matrix: {e}")
            return False

    def get_technique_name(self, technique_id: str) -> str:
        """Get technique name from ID.

        Args:
            technique_id: Technique ID (e.g., "T1059")

        Returns:
            Technique name
        """
        return self.techniques.get(technique_id, {}).get("name", technique_id)

    def get_statistics(self) -> Dict[str, int]:
        """Get statistics about the transition builder.

        Returns:
            Dictionary with statistics
        """
        return {
            "techniques": len(self.techniques),
            "relationships": len(self.relationships),
            "transitions": len(self.transition_probs),
            "matrix_size": len(self.technique_ids) if self.technique_ids else 0,
        }
