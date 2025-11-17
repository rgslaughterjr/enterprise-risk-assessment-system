"""
Comprehensive tests for Entity Extractor.

Tests cover:
- Entity extraction (CVEs, controls, assets, risks, frameworks)
- spaCy NER integration
- Regex pattern matching
- Confidence scoring
- Context extraction
- Deduplication
- Edge cases and error handling
"""

import pytest
from unittest.mock import Mock, patch, MagicMock
from pathlib import Path

from src.tools.entity_extractor import EntityExtractor


@pytest.fixture
def entity_extractor():
    """Create entity extractor instance."""
    with patch('src.tools.entity_extractor.spacy') as mock_spacy:
        mock_spacy.load.return_value = None
        extractor = EntityExtractor()
        return extractor


@pytest.fixture
def entity_extractor_with_spacy():
    """Create entity extractor with mocked spaCy."""
    with patch('src.tools.entity_extractor.SPACY_AVAILABLE', True):
        with patch('src.tools.entity_extractor.spacy') as mock_spacy:
            mock_nlp = MagicMock()
            mock_spacy.load.return_value = mock_nlp

            # Setup mock entities
            mock_doc = MagicMock()
            mock_ent = MagicMock()
            mock_ent.text = "Microsoft"
            mock_ent.label_ = "ORG"
            mock_ent.start_char = 0
            mock_ent.end_char = 9
            mock_doc.ents = [mock_ent]
            mock_nlp.return_value = mock_doc

            extractor = EntityExtractor()
            return extractor


@pytest.fixture
def sample_cve_text():
    """Sample text with CVE identifiers."""
    return """
    Security assessment identified multiple vulnerabilities:
    CVE-2024-1234 affects the web server with critical severity.
    CVE-2023-56789 was found in the database component.
    The system is also vulnerable to CVE-2024-99999.
    """


@pytest.fixture
def sample_controls_text():
    """Sample text with security controls."""
    return """
    Compliance assessment for NIST controls:
    AC-2 Account Management control is partially implemented.
    AU-12(1) audit logging requirements need attention.
    ISO 27001: A.9.2 user access management is documented.
    CIS Control 5.1 should be applied to all systems.
    PCI-DSS Requirement 8.2.3 must be enforced.
    """


@pytest.fixture
def sample_assets_text():
    """Sample text with asset mentions."""
    return """
    Infrastructure inventory includes:
    - 15 web servers running production workloads
    - 3 database servers (MySQL and PostgreSQL)
    - Cloud applications hosted on AWS
    - Network infrastructure includes routers at 192.168.1.1
    - Docker containers running on Kubernetes clusters
    - REST API endpoints for mobile applications
    """


@pytest.fixture
def sample_risks_text():
    """Sample text with risk entities."""
    return """
    Risk Assessment Summary:
    Critical threats identified include ransomware attacks.
    Several vulnerabilities discovered during penetration testing.
    High impact on business operations with medium likelihood.
    Mitigation strategies include patching and security controls.
    """


@pytest.fixture
def sample_frameworks_text():
    """Sample text with security frameworks."""
    return """
    Compliance with multiple frameworks required:
    NIST CSF provides cybersecurity framework.
    ISO/IEC 27001 certification is current.
    PCI-DSS compliance for payment processing.
    HIPAA regulations apply to health data.
    SOC 2 Type II audit completed.
    GDPR compliance for EU data protection.
    """


class TestEntityExtractorInit:
    """Test entity extractor initialization."""

    def test_init_default_model(self):
        """Test initialization with default spaCy model."""
        with patch('src.tools.entity_extractor.spacy') as mock_spacy:
            mock_spacy.load.return_value = None
            extractor = EntityExtractor()
            assert extractor.spacy_model_name == 'en_core_web_sm'

    def test_init_custom_model(self):
        """Test initialization with custom spaCy model."""
        with patch('src.tools.entity_extractor.spacy') as mock_spacy:
            mock_spacy.load.return_value = None
            extractor = EntityExtractor(spacy_model='en_core_web_lg')
            assert extractor.spacy_model_name == 'en_core_web_lg'

    def test_init_without_spacy(self):
        """Test initialization when spaCy not available."""
        with patch('src.tools.entity_extractor.SPACY_AVAILABLE', False):
            extractor = EntityExtractor()
            assert extractor.nlp is None

    def test_init_spacy_model_load_error(self):
        """Test initialization when spaCy model fails to load."""
        with patch('src.tools.entity_extractor.spacy') as mock_spacy:
            mock_spacy.load.side_effect = OSError("Model not found")
            extractor = EntityExtractor()
            assert extractor.nlp is None

    def test_patterns_defined(self):
        """Test that entity patterns are defined."""
        assert 'cve' in EntityExtractor.PATTERNS
        assert 'nist_control' in EntityExtractor.PATTERNS
        assert 'iso_control' in EntityExtractor.PATTERNS
        assert 'cis_control' in EntityExtractor.PATTERNS

    def test_asset_keywords_defined(self):
        """Test that asset keywords are defined."""
        assert 'server' in EntityExtractor.ASSET_KEYWORDS
        assert 'database' in EntityExtractor.ASSET_KEYWORDS
        assert 'application' in EntityExtractor.ASSET_KEYWORDS

    def test_risk_keywords_defined(self):
        """Test that risk keywords are defined."""
        assert 'threat' in EntityExtractor.RISK_KEYWORDS
        assert 'vulnerability' in EntityExtractor.RISK_KEYWORDS
        assert 'impact' in EntityExtractor.RISK_KEYWORDS

    def test_framework_patterns_defined(self):
        """Test that framework patterns are defined."""
        assert 'NIST' in EntityExtractor.FRAMEWORK_PATTERNS
        assert 'ISO27001' in EntityExtractor.FRAMEWORK_PATTERNS
        assert 'PCI-DSS' in EntityExtractor.FRAMEWORK_PATTERNS


class TestExtractCVEs:
    """Test CVE extraction."""

    def test_extract_single_cve(self, entity_extractor):
        """Test extracting single CVE."""
        text = "Found CVE-2024-1234 in the system"
        cves = entity_extractor.extract_cves(text)

        assert len(cves) == 1
        assert cves[0]['value'] == 'CVE-2024-1234'
        assert 0 <= cves[0]['confidence'] <= 1

    def test_extract_multiple_cves(self, entity_extractor, sample_cve_text):
        """Test extracting multiple CVEs."""
        cves = entity_extractor.extract_cves(sample_cve_text)

        assert len(cves) == 3
        cve_ids = [cve['value'] for cve in cves]
        assert 'CVE-2024-1234' in cve_ids
        assert 'CVE-2023-56789' in cve_ids
        assert 'CVE-2024-99999' in cve_ids

    def test_extract_cve_case_insensitive(self, entity_extractor):
        """Test CVE extraction is case insensitive."""
        text = "Vulnerabilities: cve-2024-1234 and CVE-2024-5678"
        cves = entity_extractor.extract_cves(text)

        assert len(cves) == 2
        # Should be normalized to uppercase
        assert all(cve['value'].startswith('CVE-') for cve in cves)

    def test_extract_cve_with_long_id(self, entity_extractor):
        """Test extracting CVE with longer ID."""
        text = "CVE-2024-1234567 is a valid CVE"
        cves = entity_extractor.extract_cves(text)

        assert len(cves) == 1
        assert cves[0]['value'] == 'CVE-2024-1234567'

    def test_extract_cve_empty_text(self, entity_extractor):
        """Test CVE extraction from empty text."""
        cves = entity_extractor.extract_cves("")
        assert cves == []

    def test_extract_cve_no_matches(self, entity_extractor):
        """Test CVE extraction with no matches."""
        text = "No vulnerabilities found in this text"
        cves = entity_extractor.extract_cves(text)
        assert cves == []

    def test_extract_cve_includes_context(self, entity_extractor):
        """Test that CVE extraction includes context."""
        text = "Critical vulnerability CVE-2024-1234 found in authentication"
        cves = entity_extractor.extract_cves(text)

        assert len(cves) == 1
        assert 'context' in cves[0]
        assert len(cves[0]['context']) > 0

    def test_extract_cve_includes_position(self, entity_extractor):
        """Test that CVE extraction includes position."""
        text = "Found CVE-2024-1234 here"
        cves = entity_extractor.extract_cves(text)

        assert len(cves) == 1
        assert 'start' in cves[0]
        assert 'end' in cves[0]
        assert cves[0]['start'] < cves[0]['end']

    def test_extract_cve_deduplication(self, entity_extractor):
        """Test that duplicate CVEs are deduplicated."""
        text = "CVE-2024-1234 and CVE-2024-1234 appear twice"
        cves = entity_extractor.extract_cves(text)

        # Should be deduplicated to single entry
        assert len(cves) == 1


class TestExtractControls:
    """Test security control extraction."""

    def test_extract_nist_control(self, entity_extractor):
        """Test extracting NIST control."""
        text = "Implement AC-2 account management control"
        controls = entity_extractor.extract_controls(text)

        assert len(controls) >= 1
        nist_controls = [c for c in controls if c['type'] == 'NIST']
        assert len(nist_controls) >= 1
        assert any('AC-2' in c['value'] for c in nist_controls)

    def test_extract_nist_control_with_enhancement(self, entity_extractor):
        """Test extracting NIST control with enhancement."""
        text = "AU-12(1) audit generation enhancement"
        controls = entity_extractor.extract_controls(text)

        nist_controls = [c for c in controls if c['type'] == 'NIST']
        assert len(nist_controls) >= 1
        assert any('AU-12(1)' in c['value'] for c in nist_controls)

    def test_extract_iso_control(self, entity_extractor):
        """Test extracting ISO 27001 control."""
        text = "ISO 27001: A.9.2 access control requirements"
        controls = entity_extractor.extract_controls(text)

        iso_controls = [c for c in controls if c['type'] == 'ISO27001']
        assert len(iso_controls) >= 1

    def test_extract_cis_control(self, entity_extractor):
        """Test extracting CIS control."""
        text = "Apply CIS Control 5.1 to all systems"
        controls = entity_extractor.extract_controls(text)

        cis_controls = [c for c in controls if c['type'] == 'CIS']
        assert len(cis_controls) >= 1

    def test_extract_pci_control(self, entity_extractor):
        """Test extracting PCI-DSS control."""
        text = "PCI-DSS Requirement 8.2.3 password complexity"
        controls = entity_extractor.extract_controls(text)

        pci_controls = [c for c in controls if c['type'] == 'PCI-DSS']
        assert len(pci_controls) >= 1

    def test_extract_multiple_control_types(self, entity_extractor, sample_controls_text):
        """Test extracting multiple control types."""
        controls = entity_extractor.extract_controls(sample_controls_text)

        assert len(controls) >= 3
        control_types = set(c['type'] for c in controls)
        assert len(control_types) >= 2  # Should have multiple types

    def test_extract_controls_empty_text(self, entity_extractor):
        """Test control extraction from empty text."""
        controls = entity_extractor.extract_controls("")
        assert controls == []

    def test_extract_controls_includes_confidence(self, entity_extractor):
        """Test that controls include confidence scores."""
        text = "Implement AC-2 control"
        controls = entity_extractor.extract_controls(text)

        assert len(controls) >= 1
        assert all('confidence' in c for c in controls)
        assert all(0 <= c['confidence'] <= 1 for c in controls)


class TestExtractAssets:
    """Test asset extraction."""

    def test_extract_server_asset(self, entity_extractor):
        """Test extracting server mentions."""
        text = "The web server is experiencing issues"
        assets = entity_extractor.extract_assets(text)

        server_assets = [a for a in assets if a['type'] == 'server']
        assert len(server_assets) >= 1

    def test_extract_database_asset(self, entity_extractor):
        """Test extracting database mentions."""
        text = "MySQL database contains sensitive data"
        assets = entity_extractor.extract_assets(text)

        db_assets = [a for a in assets if a['type'] == 'database']
        assert len(db_assets) >= 1

    def test_extract_application_asset(self, entity_extractor):
        """Test extracting application mentions."""
        text = "The mobile app needs security updates"
        assets = entity_extractor.extract_assets(text)

        app_assets = [a for a in assets if a['type'] == 'application']
        assert len(app_assets) >= 1

    def test_extract_network_asset(self, entity_extractor):
        """Test extracting network mentions."""
        text = "Network infrastructure requires monitoring"
        assets = entity_extractor.extract_assets(text)

        network_assets = [a for a in assets if a['type'] == 'network']
        assert len(network_assets) >= 1

    def test_extract_cloud_asset(self, entity_extractor):
        """Test extracting cloud mentions."""
        text = "AWS cloud services hosting our applications"
        assets = entity_extractor.extract_assets(text)

        cloud_assets = [a for a in assets if a['type'] == 'cloud']
        assert len(cloud_assets) >= 1

    def test_extract_ip_address(self, entity_extractor):
        """Test extracting IP addresses."""
        text = "Server at 192.168.1.1 is down"
        assets = entity_extractor.extract_assets(text)

        ip_assets = [a for a in assets if a['type'] == 'ip_address']
        assert len(ip_assets) >= 1
        assert ip_assets[0]['value'] == '192.168.1.1'

    def test_extract_invalid_ip_address(self, entity_extractor):
        """Test that invalid IP addresses are rejected."""
        text = "Invalid IP: 256.300.400.500"
        assets = entity_extractor.extract_assets(text)

        ip_assets = [a for a in assets if a['type'] == 'ip_address']
        # Should not extract invalid IP
        assert not any(a['value'] == '256.300.400.500' for a in ip_assets)

    def test_extract_multiple_assets(self, entity_extractor, sample_assets_text):
        """Test extracting multiple asset types."""
        assets = entity_extractor.extract_assets(sample_assets_text)

        assert len(assets) >= 5
        asset_types = set(a['type'] for a in assets)
        assert len(asset_types) >= 3

    def test_extract_assets_empty_text(self, entity_extractor):
        """Test asset extraction from empty text."""
        assets = entity_extractor.extract_assets("")
        assert assets == []

    def test_extract_assets_includes_confidence(self, entity_extractor):
        """Test that assets include confidence scores."""
        text = "Database server running MySQL"
        assets = entity_extractor.extract_assets(text)

        assert len(assets) >= 1
        assert all('confidence' in a for a in assets)
        assert all(0 <= a['confidence'] <= 1 for a in assets)


class TestExtractRisks:
    """Test risk entity extraction."""

    def test_extract_threat(self, entity_extractor):
        """Test extracting threat mentions."""
        text = "Advanced threat detected in network"
        risks = entity_extractor.extract_risks(text)

        threats = [r for r in risks if r['type'] == 'threat']
        assert len(threats) >= 1

    def test_extract_vulnerability(self, entity_extractor):
        """Test extracting vulnerability mentions."""
        text = "Critical vulnerability in authentication"
        risks = entity_extractor.extract_risks(text)

        vulns = [r for r in risks if r['type'] == 'vulnerability']
        assert len(vulns) >= 1

    def test_extract_impact(self, entity_extractor):
        """Test extracting impact mentions."""
        text = "High impact on business operations"
        risks = entity_extractor.extract_risks(text)

        impacts = [r for r in risks if r['type'] == 'impact']
        assert len(impacts) >= 1

    def test_extract_likelihood(self, entity_extractor):
        """Test extracting likelihood mentions."""
        text = "Medium likelihood of occurrence"
        risks = entity_extractor.extract_risks(text)

        likelihoods = [r for r in risks if r['type'] == 'likelihood']
        assert len(likelihoods) >= 1

    def test_extract_mitigation(self, entity_extractor):
        """Test extracting mitigation mentions."""
        text = "Mitigation strategies recommended"
        risks = entity_extractor.extract_risks(text)

        mitigations = [r for r in risks if r['type'] == 'mitigation']
        assert len(mitigations) >= 1

    def test_extract_severity_critical(self, entity_extractor):
        """Test extracting critical severity."""
        text = "Critical security issue detected"
        risks = entity_extractor.extract_risks(text)

        severities = [r for r in risks if r['type'] == 'severity']
        assert len(severities) >= 1
        assert any(r['value'] == 'critical' for r in severities)

    def test_extract_severity_levels(self, entity_extractor):
        """Test extracting all severity levels."""
        text = "Critical, high, medium, and low severity issues"
        risks = entity_extractor.extract_risks(text)

        severities = [r for r in risks if r['type'] == 'severity']
        severity_values = set(r['value'] for r in severities)
        assert 'critical' in severity_values
        assert 'high' in severity_values
        assert 'medium' in severity_values
        assert 'low' in severity_values

    def test_extract_multiple_risks(self, entity_extractor, sample_risks_text):
        """Test extracting multiple risk types."""
        risks = entity_extractor.extract_risks(sample_risks_text)

        assert len(risks) >= 4
        risk_types = set(r['type'] for r in risks)
        assert len(risk_types) >= 3

    def test_extract_risks_empty_text(self, entity_extractor):
        """Test risk extraction from empty text."""
        risks = entity_extractor.extract_risks("")
        assert risks == []


class TestExtractFrameworks:
    """Test security framework extraction."""

    def test_extract_nist_framework(self, entity_extractor):
        """Test extracting NIST framework."""
        text = "Aligned with NIST CSF requirements"
        frameworks = entity_extractor.extract_frameworks(text)

        nist = [f for f in frameworks if f['value'] == 'NIST']
        assert len(nist) >= 1

    def test_extract_iso27001(self, entity_extractor):
        """Test extracting ISO 27001."""
        text = "ISO 27001 certification required"
        frameworks = entity_extractor.extract_frameworks(text)

        iso = [f for f in frameworks if f['value'] == 'ISO27001']
        assert len(iso) >= 1

    def test_extract_pci_dss(self, entity_extractor):
        """Test extracting PCI-DSS."""
        text = "PCI-DSS compliance for payment data"
        frameworks = entity_extractor.extract_frameworks(text)

        pci = [f for f in frameworks if f['value'] == 'PCI-DSS']
        assert len(pci) >= 1

    def test_extract_hipaa(self, entity_extractor):
        """Test extracting HIPAA."""
        text = "HIPAA requirements for health data"
        frameworks = entity_extractor.extract_frameworks(text)

        hipaa = [f for f in frameworks if f['value'] == 'HIPAA']
        assert len(hipaa) >= 1

    def test_extract_gdpr(self, entity_extractor):
        """Test extracting GDPR."""
        text = "GDPR compliance for EU customers"
        frameworks = entity_extractor.extract_frameworks(text)

        gdpr = [f for f in frameworks if f['value'] == 'GDPR']
        assert len(gdpr) >= 1

    def test_extract_soc2(self, entity_extractor):
        """Test extracting SOC 2."""
        text = "SOC 2 Type II audit completed"
        frameworks = entity_extractor.extract_frameworks(text)

        soc2 = [f for f in frameworks if f['value'] == 'SOC2']
        assert len(soc2) >= 1

    def test_extract_multiple_frameworks(self, entity_extractor, sample_frameworks_text):
        """Test extracting multiple frameworks."""
        frameworks = entity_extractor.extract_frameworks(sample_frameworks_text)

        assert len(frameworks) >= 4
        framework_names = set(f['value'] for f in frameworks)
        assert len(framework_names) >= 4

    def test_extract_frameworks_empty_text(self, entity_extractor):
        """Test framework extraction from empty text."""
        frameworks = entity_extractor.extract_frameworks("")
        assert frameworks == []

    def test_extract_frameworks_includes_matched_text(self, entity_extractor):
        """Test that frameworks include matched text."""
        text = "NIST CSF framework"
        frameworks = entity_extractor.extract_frameworks(text)

        assert len(frameworks) >= 1
        assert 'matched_text' in frameworks[0]


class TestConfidenceScoring:
    """Test confidence scoring."""

    def test_cve_confidence_high(self, entity_extractor):
        """Test CVE gets high confidence in vulnerability context."""
        confidence = entity_extractor.get_entity_confidence(
            'CVE-2024-1234',
            'Critical vulnerability CVE-2024-1234 found',
            'cve'
        )
        assert confidence >= 0.8

    def test_cve_confidence_valid_format(self, entity_extractor):
        """Test valid CVE format gets good confidence."""
        confidence = entity_extractor.get_entity_confidence(
            'CVE-2024-1234',
            'Found in system',
            'cve'
        )
        assert confidence >= 0.7

    def test_control_confidence_in_context(self, entity_extractor):
        """Test control confidence in compliance context."""
        confidence = entity_extractor.get_entity_confidence(
            'AC-2',
            'Control AC-2 compliance requirement',
            'control'
        )
        assert confidence >= 0.7

    def test_asset_confidence_in_context(self, entity_extractor):
        """Test asset confidence in infrastructure context."""
        confidence = entity_extractor.get_entity_confidence(
            'server',
            'Infrastructure server resource',
            'asset'
        )
        assert confidence >= 0.6

    def test_risk_confidence_in_context(self, entity_extractor):
        """Test risk confidence in assessment context."""
        confidence = entity_extractor.get_entity_confidence(
            'threat',
            'Risk assessment of threat',
            'risk'
        )
        assert confidence >= 0.6

    def test_framework_confidence_in_context(self, entity_extractor):
        """Test framework confidence in compliance context."""
        confidence = entity_extractor.get_entity_confidence(
            'NIST',
            'Compliance with NIST framework',
            'framework'
        )
        assert confidence >= 0.8

    def test_confidence_range(self, entity_extractor):
        """Test confidence is always in valid range."""
        confidence = entity_extractor.get_entity_confidence(
            'test',
            'test context',
            'unknown'
        )
        assert 0.0 <= confidence <= 1.0

    def test_confidence_scoring_error_handling(self, entity_extractor):
        """Test confidence scoring handles errors."""
        # Should not crash with invalid input
        confidence = entity_extractor.get_entity_confidence(
            None,
            None,
            'test'
        )
        assert isinstance(confidence, float)


class TestExtractEntities:
    """Test comprehensive entity extraction."""

    def test_extract_all_entities(self, entity_extractor):
        """Test extracting all entity types."""
        text = """
        Security assessment found CVE-2024-1234 vulnerability.
        NIST AC-2 control needed for the database server.
        Critical threat with high impact identified.
        Compliance with ISO 27001 required.
        """

        entities = entity_extractor.extract_entities(text)

        assert isinstance(entities, dict)
        assert 'cves' in entities
        assert 'controls' in entities
        assert 'assets' in entities
        assert 'risks' in entities
        assert 'frameworks' in entities

    def test_extract_entities_includes_summary(self, entity_extractor):
        """Test extraction includes summary statistics."""
        text = "CVE-2024-1234 found in server. High impact threat."
        entities = entity_extractor.extract_entities(text)

        assert 'summary' in entities
        assert 'total_entities' in entities['summary']
        assert 'cve_count' in entities['summary']

    def test_extract_entities_empty_text(self, entity_extractor):
        """Test extraction from empty text."""
        entities = entity_extractor.extract_entities("")
        assert entities == {}

    def test_extract_entities_none_text(self, entity_extractor):
        """Test extraction from None."""
        entities = entity_extractor.extract_entities(None)
        assert entities == {}

    def test_extract_entities_invalid_type(self, entity_extractor):
        """Test extraction from non-string."""
        entities = entity_extractor.extract_entities(123)
        assert entities == {}


class TestSpaCyIntegration:
    """Test spaCy NER integration."""

    def test_extract_with_spacy_available(self, entity_extractor_with_spacy):
        """Test extraction when spaCy is available."""
        text = "Microsoft reported a security issue"
        entities = entity_extractor_with_spacy.extract_entities(text)

        if 'named_entities' in entities:
            assert isinstance(entities['named_entities'], list)

    def test_extract_without_spacy(self, entity_extractor):
        """Test extraction works without spaCy."""
        text = "CVE-2024-1234 vulnerability found"
        entities = entity_extractor.extract_entities(text)

        # Should still extract CVEs using regex
        assert len(entities.get('cves', [])) >= 1

    def test_spacy_entities_format(self, entity_extractor_with_spacy):
        """Test spaCy entity format."""
        if entity_extractor_with_spacy.nlp:
            text = "Test text"
            spacy_entities = entity_extractor_with_spacy._extract_spacy_entities(text)

            if spacy_entities:
                entity = spacy_entities[0]
                assert 'value' in entity
                assert 'type' in entity
                assert 'confidence' in entity


class TestUtilityMethods:
    """Test utility and helper methods."""

    def test_get_context(self, entity_extractor):
        """Test context extraction."""
        text = "This is a test sentence with CVE-2024-1234 in the middle"
        start = text.index('CVE')
        end = start + 13

        context = entity_extractor._get_context(text, start, end)

        assert isinstance(context, str)
        assert 'CVE-2024-1234' in context

    def test_get_context_at_start(self, entity_extractor):
        """Test context extraction at text start."""
        text = "CVE-2024-1234 is at the beginning"
        context = entity_extractor._get_context(text, 0, 13)

        assert isinstance(context, str)

    def test_get_context_at_end(self, entity_extractor):
        """Test context extraction at text end."""
        text = "This ends with CVE-2024-1234"
        start = text.index('CVE')
        end = len(text)

        context = entity_extractor._get_context(text, start, end)

        assert isinstance(context, str)

    def test_is_valid_ip(self, entity_extractor):
        """Test IP address validation."""
        assert entity_extractor._is_valid_ip('192.168.1.1') is True
        assert entity_extractor._is_valid_ip('10.0.0.1') is True
        assert entity_extractor._is_valid_ip('255.255.255.255') is True

    def test_is_invalid_ip(self, entity_extractor):
        """Test invalid IP address rejection."""
        assert entity_extractor._is_valid_ip('256.1.1.1') is False
        assert entity_extractor._is_valid_ip('1.1.1.256') is False
        assert entity_extractor._is_valid_ip('invalid') is False
        assert entity_extractor._is_valid_ip('1.1.1') is False

    def test_deduplicate_entities(self, entity_extractor):
        """Test entity deduplication."""
        entities = [
            {'value': 'CVE-2024-1234', 'confidence': 0.8},
            {'value': 'CVE-2024-1234', 'confidence': 0.9},
            {'value': 'CVE-2024-5678', 'confidence': 0.7},
        ]

        deduplicated = entity_extractor._deduplicate_entities(entities)

        assert len(deduplicated) == 2
        # Should keep higher confidence version
        cve_1234 = next(e for e in deduplicated if e['value'] == 'CVE-2024-1234')
        assert cve_1234['confidence'] == 0.9

    def test_deduplicate_empty_list(self, entity_extractor):
        """Test deduplication of empty list."""
        assert entity_extractor._deduplicate_entities([]) == []

    def test_generate_summary(self, entity_extractor):
        """Test summary generation."""
        entities = {
            'cves': [{'value': 'CVE-2024-1234'}],
            'controls': [{'value': 'AC-2'}, {'value': 'AU-12'}],
            'assets': [],
            'risks': [{'value': 'threat'}],
            'frameworks': [{'value': 'NIST'}],
        }

        summary = entity_extractor._generate_summary(entities)

        assert summary['cve_count'] == 1
        assert summary['control_count'] == 2
        assert summary['asset_count'] == 0
        assert summary['risk_count'] == 1
        assert summary['framework_count'] == 1
        assert summary['total_entities'] == 5

    def test_get_entity_types(self, entity_extractor):
        """Test getting supported entity types."""
        types = entity_extractor.get_entity_types()

        assert isinstance(types, list)
        assert 'cves' in types
        assert 'controls' in types
        assert 'assets' in types
        assert 'risks' in types
        assert 'frameworks' in types

    def test_get_statistics(self, entity_extractor):
        """Test getting extractor statistics."""
        stats = entity_extractor.get_statistics()

        assert isinstance(stats, dict)
        assert 'spacy_available' in stats
        assert 'spacy_model_loaded' in stats
        assert 'supported_entity_types' in stats
        assert 'control_frameworks' in stats
        assert 'security_frameworks' in stats


class TestEdgeCases:
    """Test edge cases and error handling."""

    def test_very_long_text(self, entity_extractor):
        """Test extraction from very long text."""
        long_text = "CVE-2024-1234 vulnerability " * 1000
        entities = entity_extractor.extract_entities(long_text)

        assert isinstance(entities, dict)
        assert len(entities.get('cves', [])) >= 1

    def test_special_characters(self, entity_extractor):
        """Test extraction with special characters."""
        text = "CVE-2024-1234!@# found in $%^ server&*()"
        entities = entity_extractor.extract_entities(text)

        assert len(entities.get('cves', [])) >= 1

    def test_unicode_text(self, entity_extractor):
        """Test extraction with unicode characters."""
        text = "CVE-2024-1234 vulnerability 日本語 server Ñoño"
        entities = entity_extractor.extract_entities(text)

        assert len(entities.get('cves', [])) >= 1

    def test_mixed_case_text(self, entity_extractor):
        """Test extraction is case insensitive where appropriate."""
        text = "cve-2024-1234 CRITICAL severity HIGH impact"
        entities = entity_extractor.extract_entities(text)

        assert len(entities.get('cves', [])) >= 1
        assert len(entities.get('risks', [])) >= 1

    def test_malformed_patterns(self, entity_extractor):
        """Test handling of malformed patterns."""
        text = "CVE-XXXX-YYYY not valid, CVE-2024-1234 is valid"
        cves = entity_extractor.extract_cves(text)

        # Should only extract valid CVE
        assert len(cves) == 1
        assert cves[0]['value'] == 'CVE-2024-1234'

    def test_overlapping_entities(self, entity_extractor):
        """Test handling of overlapping entities."""
        text = "server database server application"
        assets = entity_extractor.extract_assets(text)

        # Should extract all matches even if overlapping
        assert len(assets) >= 2

    def test_multiple_extractions_consistent(self, entity_extractor):
        """Test multiple extractions are consistent."""
        text = "CVE-2024-1234 in server, NIST framework"

        entities1 = entity_extractor.extract_entities(text)
        entities2 = entity_extractor.extract_entities(text)

        # Results should be consistent
        assert len(entities1.get('cves', [])) == len(entities2.get('cves', []))

    def test_whitespace_handling(self, entity_extractor):
        """Test proper whitespace handling."""
        text = "CVE-2024-1234\t\n\r found in   server"
        entities = entity_extractor.extract_entities(text)

        assert len(entities.get('cves', [])) >= 1

    def test_extraction_error_handling(self, entity_extractor):
        """Test extraction handles errors gracefully."""
        # Should not crash even with problematic input
        entities = entity_extractor.extract_entities("a" * 1000000)
        assert isinstance(entities, dict)
