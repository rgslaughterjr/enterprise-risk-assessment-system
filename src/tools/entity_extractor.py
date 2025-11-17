"""
Entity Extractor for extracting security-related entities from text.

This module provides entity extraction capabilities for:
- CVE identifiers (CVE-YYYY-NNNNN)
- Security controls (NIST, ISO, CIS)
- Assets (servers, databases, applications)
- Risks (threats, vulnerabilities, impacts)
- Security frameworks (NIST, ISO27001, PCI-DSS)
- Confidence scoring for extracted entities
"""

import logging
import re
from typing import Dict, List, Tuple, Set, Optional, Any
from collections import defaultdict

try:
    import spacy
    from spacy.language import Language
    SPACY_AVAILABLE = True
except ImportError:
    SPACY_AVAILABLE = False
    spacy = None
    Language = None

logger = logging.getLogger(__name__)


class EntityExtractor:
    """
    Enterprise-grade entity extractor for security documents.

    Features:
    - Multi-entity type extraction
    - spaCy NER integration
    - Regex pattern matching
    - Confidence scoring
    - Context-aware extraction
    - Support for multiple security frameworks
    """

    # Regex patterns for entity extraction
    PATTERNS = {
        'cve': r'CVE-\d{4}-\d{4,7}',
        'nist_control': r'(?:NIST\s+)?([A-Z]{2})-(\d{1,2})(?:\((\d+)\))?',
        'iso_control': r'(?:ISO\s*)?27001[:\s]+([A-Z])\.(\d+)(?:\.(\d+))?',
        'cis_control': r'CIS\s+Control\s+(\d+)(?:\.(\d+))?',
        'pci_control': r'PCI[-\s]?DSS\s+(?:Requirement\s+)?(\d+)(?:\.(\d+))?(?:\.(\d+))?',
        'ip_address': r'\b(?:\d{1,3}\.){3}\d{1,3}\b',
        'port': r'\bport\s+(\d{1,5})\b',
        'severity': r'\b(critical|high|medium|low)\b',
    }

    # Asset keywords and patterns
    ASSET_KEYWORDS = {
        'server': ['server', 'servers', 'web server', 'database server', 'application server'],
        'database': ['database', 'databases', 'db', 'sql server', 'mysql', 'postgresql', 'mongodb'],
        'application': ['application', 'applications', 'app', 'web app', 'mobile app'],
        'network': ['network', 'networks', 'lan', 'wan', 'vpc', 'subnet'],
        'endpoint': ['endpoint', 'endpoints', 'workstation', 'desktop', 'laptop'],
        'cloud': ['cloud', 'aws', 'azure', 'gcp', 'cloud service'],
        'container': ['container', 'docker', 'kubernetes', 'k8s', 'pod'],
        'api': ['api', 'rest api', 'graphql', 'endpoint'],
    }

    # Risk-related keywords
    RISK_KEYWORDS = {
        'threat': ['threat', 'threats', 'threat actor', 'attacker', 'adversary'],
        'vulnerability': ['vulnerability', 'vulnerabilities', 'weakness', 'exposure'],
        'impact': ['impact', 'consequence', 'damage', 'loss'],
        'likelihood': ['likelihood', 'probability', 'chance', 'risk'],
        'mitigation': ['mitigation', 'remediation', 'fix', 'patch', 'control'],
    }

    # Security frameworks
    FRAMEWORK_PATTERNS = {
        'NIST': r'\bNIST\s*(?:CSF|800-53|SP\s*800-\d+)?\b',
        'ISO27001': r'\bISO\s*/?(?:IEC\s*)?27001\b',
        'ISO27002': r'\bISO\s*/?(?:IEC\s*)?27002\b',
        'PCI-DSS': r'\bPCI[-\s]?DSS\b',
        'HIPAA': r'\bHIPAA\b',
        'GDPR': r'\bGDPR\b',
        'SOC2': r'\bSOC\s*2\b',
        'CIS': r'\bCIS\s+(?:Controls|Benchmarks?)\b',
        'COBIT': r'\bCOBIT\b',
        'FISMA': r'\bFISMA\b',
    }

    # Minimum confidence thresholds
    MIN_CONFIDENCE = 0.3
    HIGH_CONFIDENCE = 0.8

    def __init__(self, spacy_model: str = 'en_core_web_sm'):
        """
        Initialize entity extractor.

        Args:
            spacy_model: Name of spaCy model to load
        """
        self.spacy_model_name = spacy_model
        self.nlp = None
        self._load_spacy_model()

    def _load_spacy_model(self):
        """Load spaCy model for NER."""
        if not SPACY_AVAILABLE:
            logger.warning("spaCy not available, using regex-only extraction")
            return

        try:
            # Validate spaCy API before use
            if not hasattr(spacy, 'load'):
                logger.warning("spaCy API incompatible, using regex-only extraction")
                return

            self.nlp = spacy.load(self.spacy_model_name)
            logger.info(f"Loaded spaCy model: {self.spacy_model_name}")

        except OSError as e:
            logger.warning(
                f"Could not load spaCy model '{self.spacy_model_name}': {e}. "
                "Using regex-only extraction. "
                f"Install with: python -m spacy download {self.spacy_model_name}"
            )
        except Exception as e:
            logger.warning(f"Error loading spaCy model: {e}. Using regex-only extraction")

    def extract_entities(self, text: str) -> Dict[str, Any]:
        """
        Extract all entity types from text.

        Args:
            text: Text to extract entities from

        Returns:
            Dictionary with entity types and their extracted values with confidence
        """
        if not text or not isinstance(text, str):
            return {}

        try:
            entities = {
                'cves': self.extract_cves(text),
                'controls': self.extract_controls(text),
                'assets': self.extract_assets(text),
                'risks': self.extract_risks(text),
                'frameworks': self.extract_frameworks(text),
            }

            # Add spaCy NER entities if available
            if self.nlp:
                entities['named_entities'] = self._extract_spacy_entities(text)

            # Add summary statistics
            entities['summary'] = self._generate_summary(entities)

            return entities

        except Exception as e:
            logger.error(f"Error extracting entities: {e}")
            return {}

    def extract_cves(self, text: str) -> List[Dict[str, Any]]:
        """
        Extract CVE identifiers from text.

        Args:
            text: Text to extract CVEs from

        Returns:
            List of CVE entities with confidence scores
        """
        if not text:
            return []

        try:
            cves = []
            pattern = re.compile(self.PATTERNS['cve'], re.IGNORECASE)

            for match in pattern.finditer(text):
                cve_id = match.group(0).upper()
                context = self._get_context(text, match.start(), match.end())
                confidence = self.get_entity_confidence(cve_id, context, 'cve')

                cves.append({
                    'value': cve_id,
                    'confidence': confidence,
                    'start': match.start(),
                    'end': match.end(),
                    'context': context,
                })

            # Deduplicate while preserving highest confidence
            cves = self._deduplicate_entities(cves)

            return cves

        except Exception as e:
            logger.error(f"Error extracting CVEs: {e}")
            return []

    def extract_controls(self, text: str) -> List[Dict[str, Any]]:
        """
        Extract security control identifiers from text.

        Args:
            text: Text to extract controls from

        Returns:
            List of control entities with confidence scores
        """
        if not text:
            return []

        try:
            controls = []

            # Extract NIST controls
            controls.extend(self._extract_nist_controls(text))

            # Extract ISO controls
            controls.extend(self._extract_iso_controls(text))

            # Extract CIS controls
            controls.extend(self._extract_cis_controls(text))

            # Extract PCI-DSS controls
            controls.extend(self._extract_pci_controls(text))

            # Deduplicate
            controls = self._deduplicate_entities(controls)

            return controls

        except Exception as e:
            logger.error(f"Error extracting controls: {e}")
            return []

    def extract_assets(self, text: str) -> List[Dict[str, Any]]:
        """
        Extract asset mentions from text.

        Args:
            text: Text to extract assets from

        Returns:
            List of asset entities with confidence scores
        """
        if not text:
            return []

        try:
            assets = []
            text_lower = text.lower()

            for asset_type, keywords in self.ASSET_KEYWORDS.items():
                for keyword in keywords:
                    pattern = re.compile(r'\b' + re.escape(keyword) + r'\b', re.IGNORECASE)

                    for match in pattern.finditer(text):
                        context = self._get_context(text, match.start(), match.end())
                        confidence = self.get_entity_confidence(
                            match.group(0),
                            context,
                            'asset'
                        )

                        assets.append({
                            'value': match.group(0),
                            'type': asset_type,
                            'confidence': confidence,
                            'start': match.start(),
                            'end': match.end(),
                            'context': context,
                        })

            # Extract IP addresses as network assets
            ip_pattern = re.compile(self.PATTERNS['ip_address'])
            for match in ip_pattern.finditer(text):
                # Validate IP address
                if self._is_valid_ip(match.group(0)):
                    context = self._get_context(text, match.start(), match.end())
                    assets.append({
                        'value': match.group(0),
                        'type': 'ip_address',
                        'confidence': 0.9,
                        'start': match.start(),
                        'end': match.end(),
                        'context': context,
                    })

            # Deduplicate
            assets = self._deduplicate_entities(assets)

            return assets

        except Exception as e:
            logger.error(f"Error extracting assets: {e}")
            return []

    def extract_risks(self, text: str) -> List[Dict[str, Any]]:
        """
        Extract risk-related entities from text.

        Args:
            text: Text to extract risks from

        Returns:
            List of risk entities with confidence scores
        """
        if not text:
            return []

        try:
            risks = []

            for risk_type, keywords in self.RISK_KEYWORDS.items():
                for keyword in keywords:
                    pattern = re.compile(r'\b' + re.escape(keyword) + r'\b', re.IGNORECASE)

                    for match in pattern.finditer(text):
                        context = self._get_context(text, match.start(), match.end())
                        confidence = self.get_entity_confidence(
                            match.group(0),
                            context,
                            'risk'
                        )

                        risks.append({
                            'value': match.group(0),
                            'type': risk_type,
                            'confidence': confidence,
                            'start': match.start(),
                            'end': match.end(),
                            'context': context,
                        })

            # Extract severity levels
            severity_pattern = re.compile(self.PATTERNS['severity'], re.IGNORECASE)
            for match in severity_pattern.finditer(text):
                context = self._get_context(text, match.start(), match.end())
                risks.append({
                    'value': match.group(0).lower(),
                    'type': 'severity',
                    'confidence': 0.95,
                    'start': match.start(),
                    'end': match.end(),
                    'context': context,
                })

            # Deduplicate
            risks = self._deduplicate_entities(risks)

            return risks

        except Exception as e:
            logger.error(f"Error extracting risks: {e}")
            return []

    def extract_frameworks(self, text: str) -> List[Dict[str, Any]]:
        """
        Extract security framework mentions from text.

        Args:
            text: Text to extract frameworks from

        Returns:
            List of framework entities with confidence scores
        """
        if not text:
            return []

        try:
            frameworks = []

            for framework_name, pattern_str in self.FRAMEWORK_PATTERNS.items():
                pattern = re.compile(pattern_str, re.IGNORECASE)

                for match in pattern.finditer(text):
                    context = self._get_context(text, match.start(), match.end())
                    confidence = self.get_entity_confidence(
                        match.group(0),
                        context,
                        'framework'
                    )

                    frameworks.append({
                        'value': framework_name,
                        'matched_text': match.group(0),
                        'confidence': confidence,
                        'start': match.start(),
                        'end': match.end(),
                        'context': context,
                    })

            # Deduplicate
            frameworks = self._deduplicate_entities(frameworks)

            return frameworks

        except Exception as e:
            logger.error(f"Error extracting frameworks: {e}")
            return []

    def get_entity_confidence(
        self,
        entity: str,
        context: str,
        entity_type: str
    ) -> float:
        """
        Calculate confidence score for an entity based on context.

        Args:
            entity: The extracted entity
            context: Surrounding text context
            entity_type: Type of entity (cve, control, asset, etc.)

        Returns:
            Confidence score (0.0-1.0)
        """
        try:
            confidence = 0.5  # Base confidence

            # CVE-specific confidence
            if entity_type == 'cve':
                # Valid CVE format gets high base confidence
                if re.match(r'^CVE-\d{4}-\d{4,7}$', entity, re.IGNORECASE):
                    confidence = 0.85

                    # Check for CVE-related context
                    context_lower = context.lower()
                    if any(word in context_lower for word in ['vulnerability', 'cve', 'exploit']):
                        confidence = min(1.0, confidence + 0.1)

            # Control-specific confidence
            elif entity_type == 'control':
                confidence = 0.75
                context_lower = context.lower()
                if any(word in context_lower for word in ['control', 'requirement', 'compliance']):
                    confidence = min(1.0, confidence + 0.15)

            # Asset-specific confidence
            elif entity_type == 'asset':
                confidence = 0.6
                context_lower = context.lower()
                if any(word in context_lower for word in ['system', 'resource', 'infrastructure']):
                    confidence = min(1.0, confidence + 0.2)

            # Risk-specific confidence
            elif entity_type == 'risk':
                confidence = 0.65
                context_lower = context.lower()
                if any(word in context_lower for word in ['risk', 'assessment', 'analysis']):
                    confidence = min(1.0, confidence + 0.2)

            # Framework-specific confidence
            elif entity_type == 'framework':
                confidence = 0.8
                context_lower = context.lower()
                if any(word in context_lower for word in ['compliance', 'standard', 'framework']):
                    confidence = min(1.0, confidence + 0.15)

            # Ensure confidence is in valid range
            confidence = max(0.0, min(1.0, confidence))

            return round(confidence, 2)

        except Exception as e:
            logger.error(f"Error calculating confidence: {e}")
            return 0.5

    def _extract_nist_controls(self, text: str) -> List[Dict[str, Any]]:
        """Extract NIST control identifiers."""
        controls = []
        pattern = re.compile(self.PATTERNS['nist_control'], re.IGNORECASE)

        for match in pattern.finditer(text):
            control_id = f"{match.group(1)}-{match.group(2)}"
            if match.group(3):
                control_id += f"({match.group(3)})"

            context = self._get_context(text, match.start(), match.end())
            confidence = self.get_entity_confidence(control_id, context, 'control')

            controls.append({
                'value': control_id,
                'type': 'NIST',
                'confidence': confidence,
                'start': match.start(),
                'end': match.end(),
                'context': context,
            })

        return controls

    def _extract_iso_controls(self, text: str) -> List[Dict[str, Any]]:
        """Extract ISO 27001 control identifiers."""
        controls = []
        pattern = re.compile(self.PATTERNS['iso_control'], re.IGNORECASE)

        for match in pattern.finditer(text):
            control_id = f"A.{match.group(2)}"
            if match.group(3):
                control_id += f".{match.group(3)}"

            context = self._get_context(text, match.start(), match.end())
            confidence = self.get_entity_confidence(control_id, context, 'control')

            controls.append({
                'value': control_id,
                'type': 'ISO27001',
                'confidence': confidence,
                'start': match.start(),
                'end': match.end(),
                'context': context,
            })

        return controls

    def _extract_cis_controls(self, text: str) -> List[Dict[str, Any]]:
        """Extract CIS control identifiers."""
        controls = []
        pattern = re.compile(self.PATTERNS['cis_control'], re.IGNORECASE)

        for match in pattern.finditer(text):
            control_id = f"CIS-{match.group(1)}"
            if match.group(2):
                control_id += f".{match.group(2)}"

            context = self._get_context(text, match.start(), match.end())
            confidence = self.get_entity_confidence(control_id, context, 'control')

            controls.append({
                'value': control_id,
                'type': 'CIS',
                'confidence': confidence,
                'start': match.start(),
                'end': match.end(),
                'context': context,
            })

        return controls

    def _extract_pci_controls(self, text: str) -> List[Dict[str, Any]]:
        """Extract PCI-DSS control identifiers."""
        controls = []
        pattern = re.compile(self.PATTERNS['pci_control'], re.IGNORECASE)

        for match in pattern.finditer(text):
            control_id = f"PCI-DSS-{match.group(1)}"
            if match.group(2):
                control_id += f".{match.group(2)}"
            if match.group(3):
                control_id += f".{match.group(3)}"

            context = self._get_context(text, match.start(), match.end())
            confidence = self.get_entity_confidence(control_id, context, 'control')

            controls.append({
                'value': control_id,
                'type': 'PCI-DSS',
                'confidence': confidence,
                'start': match.start(),
                'end': match.end(),
                'context': context,
            })

        return controls

    def _extract_spacy_entities(self, text: str) -> List[Dict[str, Any]]:
        """Extract named entities using spaCy NER."""
        if not self.nlp:
            return []

        try:
            doc = self.nlp(text)
            entities = []

            for ent in doc.ents:
                entities.append({
                    'value': ent.text,
                    'type': ent.label_,
                    'confidence': 0.7,  # spaCy doesn't provide confidence by default
                    'start': ent.start_char,
                    'end': ent.end_char,
                })

            return entities

        except Exception as e:
            logger.error(f"Error extracting spaCy entities: {e}")
            return []

    def _get_context(
        self,
        text: str,
        start: int,
        end: int,
        window: int = 50
    ) -> str:
        """
        Get surrounding context for an entity.

        Args:
            text: Full text
            start: Entity start position
            end: Entity end position
            window: Context window size (characters before/after)

        Returns:
            Context string
        """
        try:
            context_start = max(0, start - window)
            context_end = min(len(text), end + window)
            return text[context_start:context_end].strip()
        except Exception:
            return ""

    def _deduplicate_entities(
        self,
        entities: List[Dict[str, Any]]
    ) -> List[Dict[str, Any]]:
        """
        Remove duplicate entities, keeping highest confidence.

        Args:
            entities: List of entity dictionaries

        Returns:
            Deduplicated list
        """
        if not entities:
            return []

        # Group by value
        entity_map = {}
        for entity in entities:
            value = entity.get('value', '')
            if value not in entity_map:
                entity_map[value] = entity
            else:
                # Keep entity with higher confidence
                if entity.get('confidence', 0) > entity_map[value].get('confidence', 0):
                    entity_map[value] = entity

        return list(entity_map.values())

    def _is_valid_ip(self, ip_str: str) -> bool:
        """
        Validate IP address format.

        Args:
            ip_str: IP address string

        Returns:
            True if valid IP address
        """
        try:
            parts = ip_str.split('.')
            if len(parts) != 4:
                return False

            for part in parts:
                num = int(part)
                if num < 0 or num > 255:
                    return False

            return True

        except (ValueError, AttributeError):
            return False

    def _generate_summary(self, entities: Dict[str, Any]) -> Dict[str, int]:
        """
        Generate summary statistics for extracted entities.

        Args:
            entities: Dictionary of extracted entities

        Returns:
            Summary statistics
        """
        summary = {
            'total_entities': 0,
            'cve_count': len(entities.get('cves', [])),
            'control_count': len(entities.get('controls', [])),
            'asset_count': len(entities.get('assets', [])),
            'risk_count': len(entities.get('risks', [])),
            'framework_count': len(entities.get('frameworks', [])),
        }

        summary['total_entities'] = sum([
            summary['cve_count'],
            summary['control_count'],
            summary['asset_count'],
            summary['risk_count'],
            summary['framework_count'],
        ])

        return summary

    def get_entity_types(self) -> List[str]:
        """
        Get list of supported entity types.

        Returns:
            List of entity type names
        """
        return ['cves', 'controls', 'assets', 'risks', 'frameworks']

    def get_statistics(self) -> Dict[str, Any]:
        """
        Get extractor statistics and configuration.

        Returns:
            Dictionary with extractor information
        """
        return {
            'spacy_available': SPACY_AVAILABLE,
            'spacy_model_loaded': self.nlp is not None,
            'spacy_model_name': self.spacy_model_name,
            'supported_entity_types': self.get_entity_types(),
            'control_frameworks': ['NIST', 'ISO27001', 'CIS', 'PCI-DSS'],
            'security_frameworks': list(self.FRAMEWORK_PATTERNS.keys()),
            'min_confidence': self.MIN_CONFIDENCE,
            'high_confidence_threshold': self.HIGH_CONFIDENCE,
        }
