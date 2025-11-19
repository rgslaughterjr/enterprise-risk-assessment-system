"""MITRE ATT&CK client for mapping CVEs to techniques and tactics.

This client uses the MITRE ATT&CK framework to map vulnerabilities to
attack techniques, tactics, and threat actor TTPs.

Uses cached enterprise-attack.json for offline operation.
"""

import sys
from pathlib import Path

# Ensure src is in path for absolute imports
_src_path = str(Path(__file__).parent.parent)
if _src_path not in sys.path:
    sys.path.insert(0, _src_path)

import os
import json
from typing import List, Dict, Optional, Any
from pathlib import Path
import logging

from models.schemas import MITRETechnique

logger = logging.getLogger(__name__)


class MITREClient:
    """Client for MITRE ATT&CK framework data.

    Provides methods to map CVEs to techniques, search tactics, and
    retrieve threat actor information from the ATT&CK framework.
    """

    def __init__(self, data_file: Optional[str] = None):
        """Initialize MITRE ATT&CK client.

        Args:
            data_file: Path to enterprise-attack.json file.
                      If not provided, looks in common locations.
        """
        self.data_file = data_file
        self.attack_data: Optional[Dict] = None
        self.techniques: Dict[str, Dict] = {}
        self.tactics: Dict[str, Dict] = {}
        self.groups: Dict[str, Dict] = {}
        self.software: Dict[str, Dict] = {}

        # Try to find data file
        if not self.data_file:
            self.data_file = self._find_data_file()

        if self.data_file and os.path.exists(self.data_file):
            self._load_data()
        else:
            logger.warning(
                f"MITRE ATT&CK data file not found. "
                f"Some features will be limited. "
                f"Searched: {self.data_file}"
            )

    def _find_data_file(self) -> Optional[str]:
        """Try to find enterprise-attack.json in common locations.

        Returns:
            Path to data file or None
        """
        # Check common locations
        possible_paths = [
            # User's ai-agent-course directory (from context)
            "/home/user/enterprise-attack.json",
            "C:/Users/richa/Documents/ai-agent-course/enterprise-attack.json",
            # Current directory and parent
            "./enterprise-attack.json",
            "../enterprise-attack.json",
            "../../enterprise-attack.json",
            # User home
            os.path.expanduser("~/enterprise-attack.json"),
        ]

        for path in possible_paths:
            if os.path.exists(path):
                logger.info(f"Found MITRE ATT&CK data at: {path}")
                return path

        return None

    def _load_data(self) -> None:
        """Load and parse MITRE ATT&CK data from JSON file."""
        try:
            logger.info(f"Loading MITRE ATT&CK data from {self.data_file}")

            with open(self.data_file, "r", encoding="utf-8") as f:
                self.attack_data = json.load(f)

            # Parse objects by type
            objects = self.attack_data.get("objects", [])

            for obj in objects:
                obj_type = obj.get("type")

                if obj_type == "attack-pattern":
                    # Technique
                    external_refs = obj.get("external_references", [])
                    tech_id = None
                    for ref in external_refs:
                        if ref.get("source_name") == "mitre-attack":
                            tech_id = ref.get("external_id")
                            break

                    if tech_id:
                        self.techniques[tech_id] = obj

                elif obj_type == "x-mitre-tactic":
                    # Tactic
                    tactic_name = obj.get("x_mitre_shortname")
                    if tactic_name:
                        self.tactics[tactic_name] = obj

                elif obj_type == "intrusion-set":
                    # Threat actor group
                    group_name = obj.get("name")
                    if group_name:
                        self.groups[group_name] = obj

                elif obj_type == "malware" or obj_type == "tool":
                    # Software
                    software_name = obj.get("name")
                    if software_name:
                        self.software[software_name] = obj

            logger.info(
                f"Loaded MITRE ATT&CK data: "
                f"{len(self.techniques)} techniques, "
                f"{len(self.tactics)} tactics, "
                f"{len(self.groups)} groups, "
                f"{len(self.software)} software"
            )

        except Exception as e:
            logger.error(f"Error loading MITRE ATT&CK data: {e}")
            self.attack_data = None

    def get_technique(self, technique_id: str) -> Optional[MITRETechnique]:
        """Get details for a specific ATT&CK technique.

        Args:
            technique_id: Technique ID (e.g., "T1059", "T1059.001")

        Returns:
            MITRETechnique object or None if not found

        Example:
            >>> client = MITREClient()
            >>> technique = client.get_technique("T1059")
            >>> if technique:
            ...     print(f"{technique.name}: {technique.description}")
        """
        if technique_id not in self.techniques:
            logger.warning(f"Technique {technique_id} not found")
            return None

        tech = self.techniques[technique_id]

        # Extract kill chain phases (tactics)
        tactics = []
        for phase in tech.get("kill_chain_phases", []):
            if phase.get("kill_chain_name") == "mitre-attack":
                tactics.append(phase.get("phase_name", ""))

        # Extract platforms
        platforms = tech.get("x_mitre_platforms", [])

        return MITRETechnique(
            technique_id=technique_id,
            name=tech.get("name", ""),
            description=tech.get("description", ""),
            tactics=tactics,
            platforms=platforms,
        )

    def search_techniques(self, keyword: str) -> List[MITRETechnique]:
        """Search for techniques by keyword.

        Args:
            keyword: Keyword to search in technique names and descriptions

        Returns:
            List of matching MITRETechnique objects

        Example:
            >>> client = MITREClient()
            >>> techniques = client.search_techniques("command injection")
            >>> for tech in techniques:
            ...     print(f"{tech.technique_id}: {tech.name}")
        """
        keyword_lower = keyword.lower()
        results = []

        for tech_id, tech in self.techniques.items():
            name = tech.get("name", "").lower()
            description = tech.get("description", "").lower()

            if keyword_lower in name or keyword_lower in description:
                technique = self.get_technique(tech_id)
                if technique:
                    results.append(technique)

        logger.info(f"Found {len(results)} techniques matching '{keyword}'")
        return results

    def map_cve_to_techniques(self, cve_id: str, cve_description: str = "") -> List[MITRETechnique]:
        """Map a CVE to potential MITRE ATT&CK techniques.

        Uses keyword matching from CVE description to suggest relevant techniques.

        Args:
            cve_id: CVE identifier
            cve_description: CVE description text

        Returns:
            List of potentially relevant MITRETechnique objects

        Example:
            >>> client = MITREClient()
            >>> techniques = client.map_cve_to_techniques(
            ...     "CVE-2024-1234",
            ...     "Remote code execution via command injection"
            ... )
            >>> for tech in techniques:
            ...     print(f"{tech.technique_id}: {tech.name}")
        """
        if not cve_description:
            logger.warning(f"No description provided for {cve_id}, cannot map to techniques")
            return []

        # Keyword mapping for common vulnerability types
        keyword_mappings = {
            "command injection": ["T1059"],  # Command and Scripting Interpreter
            "sql injection": ["T1190"],  # Exploit Public-Facing Application
            "remote code execution": ["T1203", "T1210"],  # Exploitation for Client/Remote Services
            "privilege escalation": ["T1068"],  # Exploitation for Privilege Escalation
            "authentication bypass": ["T1078"],  # Valid Accounts
            "buffer overflow": ["T1203"],  # Exploitation for Client Execution
            "cross-site scripting": ["T1189"],  # Drive-by Compromise
            "path traversal": ["T1083"],  # File and Directory Discovery
            "deserialization": ["T1203"],  # Exploitation for Client Execution
            "memory corruption": ["T1203"],
            "denial of service": ["T1499"],  # Endpoint Denial of Service
        }

        description_lower = cve_description.lower()
        matched_techniques = set()

        # Check for keyword matches
        for keyword, tech_ids in keyword_mappings.items():
            if keyword in description_lower:
                matched_techniques.update(tech_ids)

        # Get technique objects
        results = []
        for tech_id in matched_techniques:
            technique = self.get_technique(tech_id)
            if technique:
                results.append(technique)

        logger.info(f"Mapped {cve_id} to {len(results)} techniques")
        return results

    def get_group(self, group_name: str) -> Optional[Dict[str, Any]]:
        """Get details for a threat actor group.

        Args:
            group_name: Group name (e.g., "APT29", "Lazarus Group")

        Returns:
            Dictionary with group details or None if not found

        Example:
            >>> client = MITREClient()
            >>> group = client.get_group("APT29")
            >>> if group:
            ...     print(f"Description: {group['description']}")
        """
        # Try exact match first
        if group_name in self.groups:
            return self.groups[group_name]

        # Try case-insensitive partial match
        group_lower = group_name.lower()
        for name, group in self.groups.items():
            if group_lower in name.lower():
                return group

            # Check aliases
            aliases = group.get("aliases", [])
            if any(group_lower in alias.lower() for alias in aliases):
                return group

        logger.warning(f"Group {group_name} not found")
        return None

    def get_group_techniques(self, group_name: str) -> List[str]:
        """Get techniques used by a threat actor group.

        Args:
            group_name: Group name

        Returns:
            List of technique IDs used by the group

        Example:
            >>> client = MITREClient()
            >>> techniques = client.get_group_techniques("APT29")
            >>> print(f"APT29 uses {len(techniques)} techniques")
        """
        group = self.get_group(group_name)
        if not group:
            return []

        # In ATT&CK data, group-technique relationships are in separate relationship objects
        # For now, return empty list (would need relationship parsing)
        # This is a simplified implementation
        logger.info(f"Retrieved techniques for group {group_name}")
        return []

    def get_tactics(self) -> List[Dict[str, Any]]:
        """Get all ATT&CK tactics.

        Returns:
            List of tactic dictionaries

        Example:
            >>> client = MITREClient()
            >>> tactics = client.get_tactics()
            >>> for tactic in tactics:
            ...     print(tactic['x_mitre_shortname'])
        """
        return list(self.tactics.values())

    def get_techniques_by_tactic(self, tactic_name: str) -> List[MITRETechnique]:
        """Get all techniques for a specific tactic.

        Args:
            tactic_name: Tactic short name (e.g., "initial-access", "execution")

        Returns:
            List of MITRETechnique objects

        Example:
            >>> client = MITREClient()
            >>> techniques = client.get_techniques_by_tactic("initial-access")
            >>> print(f"Found {len(techniques)} initial access techniques")
        """
        results = []

        for tech_id, tech in self.techniques.items():
            for phase in tech.get("kill_chain_phases", []):
                if (
                    phase.get("kill_chain_name") == "mitre-attack"
                    and phase.get("phase_name") == tactic_name
                ):
                    technique = self.get_technique(tech_id)
                    if technique:
                        results.append(technique)
                    break

        logger.info(f"Found {len(results)} techniques for tactic '{tactic_name}'")
        return results

    def get_statistics(self) -> Dict[str, int]:
        """Get statistics about loaded ATT&CK data.

        Returns:
            Dictionary with counts of techniques, tactics, groups, etc.
        """
        return {
            "techniques": len(self.techniques),
            "tactics": len(self.tactics),
            "groups": len(self.groups),
            "software": len(self.software),
        }
