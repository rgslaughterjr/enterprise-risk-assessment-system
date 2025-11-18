"""Tests for Risk Assessment Framework Adapters."""

import pytest
from src.frameworks.nist_ai_rmf_adapter import NISTAIRMFAdapter
from src.frameworks.octave_adapter import OCTAVEAdapter, AssetCriticality, ImpactArea
from src.frameworks.iso31000_adapter import (
    ISO31000Adapter,
    LikelihoodLevel,
    ConsequenceLevel,
)


class TestNISTAIRMFAdapter:
    """Test suite for NIST AI RMF Adapter."""

    @pytest.fixture
    def adapter(self):
        """Create NIST AI RMF adapter instance."""
        return NISTAIRMFAdapter()

    @pytest.fixture
    def sample_cve(self):
        """Create sample CVE data."""
        return {
            "id": "CVE-2024-1234",
            "cvss_score": 7.5,
            "description": "SQL injection vulnerability",
        }

    @pytest.fixture
    def sample_asset(self):
        """Create sample asset data."""
        return {
            "id": "ASSET-001",
            "name": "ML Model API",
            "type": "AI/ML system",
        }

    def test_init(self, adapter):
        """Test adapter initialization."""
        assert adapter is not None
        assert len(adapter.TRUSTWORTHINESS_CHARACTERISTICS) == 7

    def test_score_ai_risk_basic(self, adapter):
        """Test basic AI risk scoring."""
        assessment = adapter.score_ai_risk()

        assert "framework" in assessment
        assert assessment["framework"] == "NIST AI RMF 1.0"
        assert "overall_score" in assessment
        assert "risk_level" in assessment
        assert "functions" in assessment

    def test_score_ai_risk_with_cve(self, adapter, sample_cve, sample_asset):
        """Test AI risk scoring with CVE data."""
        assessment = adapter.score_ai_risk(cve=sample_cve, asset=sample_asset)

        assert assessment["overall_score"] > 5.0
        assert "GOVERN" in assessment["functions"]
        assert "MAP" in assessment["functions"]

    def test_four_core_functions(self, adapter):
        """Test that all four NIST AI RMF functions are included."""
        assessment = adapter.score_ai_risk()

        assert "GOVERN" in assessment["functions"]
        assert "MAP" in assessment["functions"]
        assert "MEASURE" in assessment["functions"]
        assert "MANAGE" in assessment["functions"]

    def test_govern_function_with_policy(self, adapter):
        """Test GOVERN function with AI policy."""
        context = {"has_ai_policy": True, "has_oversight_body": True}
        assessment = adapter.score_ai_risk(context=context)

        govern = assessment["functions"]["GOVERN"]
        assert govern["score"] > 5.0
        assert govern["category"] == "Governance"

    def test_map_function_high_severity_cve(self, adapter):
        """Test MAP function with high-severity CVE."""
        cve = {"id": "CVE-2024-9999", "cvss_score": 9.8}
        assessment = adapter.score_ai_risk(cve=cve)

        map_func = assessment["functions"]["MAP"]
        assert map_func["score"] >= 7.0

    def test_measure_function_impact_likelihood(self, adapter):
        """Test MEASURE function with impact and likelihood."""
        context = {"estimated_impact": "high", "estimated_likelihood": "high"}
        assessment = adapter.score_ai_risk(context=context)

        measure = assessment["functions"]["MEASURE"]
        assert measure["score"] >= 6.0
        assert measure["impact_level"] == "high"

    def test_manage_function_with_controls(self, adapter):
        """Test MANAGE function with controls in place."""
        context = {
            "has_monitoring": True,
            "has_incident_response": True,
            "has_controls": True,
        }
        assessment = adapter.score_ai_risk(context=context)

        manage = assessment["functions"]["MANAGE"]
        assert manage["score"] >= 8.0

    def test_trustworthiness_assessment(self, adapter):
        """Test trustworthiness characteristic assessment."""
        assessment = adapter.score_ai_risk()

        trust = assessment["trustworthiness_assessment"]
        assert len(trust) == 7
        assert "valid_reliable" in trust
        assert "safe" in trust
        assert "secure_resilient" in trust

    def test_trustworthiness_reduced_with_cve(self, adapter, sample_cve):
        """Test that trustworthiness is reduced with CVE."""
        assessment_no_cve = adapter.score_ai_risk()
        assessment_with_cve = adapter.score_ai_risk(cve=sample_cve)

        avg_no_cve = sum(assessment_no_cve["trustworthiness_assessment"].values()) / 7
        avg_with_cve = sum(assessment_with_cve["trustworthiness_assessment"].values()) / 7

        assert avg_with_cve < avg_no_cve

    def test_ai_category_general(self, adapter):
        """Test assessment for general AI system."""
        context = {"ai_system_category": "general"}
        assessment = adapter.score_ai_risk(context=context)

        assert assessment["ai_category"] == "general"

    def test_ai_category_high_risk(self, adapter):
        """Test assessment for high-risk AI system."""
        context = {"ai_system_category": "high_risk"}
        assessment = adapter.score_ai_risk(context=context)

        assert assessment["ai_category"] == "high_risk"
        # Higher risk systems should have higher MAP scores
        assert assessment["functions"]["MAP"]["score"] > 5.0

    def test_recommendations_high_risk(self, adapter):
        """Test recommendations for high-risk assessment."""
        cve = {"cvss_score": 9.5}
        assessment = adapter.score_ai_risk(cve=cve)

        assert len(assessment["recommendations"]) > 0
        assert assessment["overall_score"] >= 6.0  # High CVSS should result in elevated score

    def test_risk_level_mapping(self, adapter):
        """Test risk level mapping from scores."""
        # Critical
        assert adapter._score_to_risk_level(9.0) == "Critical"
        # High
        assert adapter._score_to_risk_level(7.0) == "High"
        # Medium
        assert adapter._score_to_risk_level(5.0) == "Medium"
        # Low
        assert adapter._score_to_risk_level(2.0) == "Low"

    def test_confidence_score(self, adapter):
        """Test that assessment includes confidence score."""
        assessment = adapter.score_ai_risk()

        assert "confidence" in assessment
        assert 0.0 <= assessment["confidence"] <= 1.0

    def test_timestamp(self, adapter):
        """Test that assessment includes timestamp."""
        assessment = adapter.score_ai_risk()

        assert "assessed_at" in assessment


class TestOCTAVEAdapter:
    """Test suite for OCTAVE Allegro Adapter."""

    @pytest.fixture
    def adapter(self):
        """Create OCTAVE adapter instance."""
        return OCTAVEAdapter()

    @pytest.fixture
    def sample_cve(self):
        """Create sample CVE data."""
        return {
            "id": "CVE-2024-5678",
            "cvss_score": 8.0,
            "description": "Remote code execution",
        }

    @pytest.fixture
    def sample_asset(self):
        """Create sample asset data."""
        return {
            "id": "ASSET-002",
            "name": "Customer Database",
            "type": "database",
            "criticality": "high",
        }

    def test_init(self, adapter):
        """Test adapter initialization."""
        assert adapter is not None
        assert len(adapter.IMPACT_SCALES) == 5

    def test_assess_risk_basic(self, adapter):
        """Test basic OCTAVE risk assessment."""
        assessment = adapter.assess_risk()

        assert assessment["framework"] == "OCTAVE Allegro"
        assert "overall_score" in assessment
        assert "risk_level" in assessment
        assert "phases" in assessment

    def test_three_phases_present(self, adapter):
        """Test that all three OCTAVE phases are included."""
        assessment = adapter.assess_risk()

        assert "establish_drivers" in assessment["phases"]
        assert "profile_assets" in assessment["phases"]
        assert "identify_threats" in assessment["phases"]

    def test_establish_drivers_phase(self, adapter):
        """Test Phase 1: Establish Drivers."""
        context = {
            "business_objectives": ["Protect data", "Ensure availability"],
            "risk_tolerance": "low",
        }
        assessment = adapter.assess_risk(context=context)

        drivers = assessment["phases"]["establish_drivers"]
        assert "business_objectives" in drivers
        assert "risk_tolerance" in drivers
        assert drivers["risk_tolerance"] == "low"

    def test_profile_assets_phase(self, adapter, sample_asset):
        """Test Phase 2: Profile Assets."""
        assessment = adapter.assess_risk(asset=sample_asset)

        profile = assessment["phases"]["profile_assets"]
        assert "asset_id" in profile
        assert "criticality" in profile
        assert "security_requirements" in profile

    def test_asset_criticality_levels(self, adapter):
        """Test different asset criticality levels."""
        low_asset = {"criticality": "low"}
        high_asset = {"criticality": "critical"}

        assessment_low = adapter.assess_risk(asset=low_asset)
        assessment_high = adapter.assess_risk(asset=high_asset)

        assert assessment_high["overall_score"] > assessment_low["overall_score"]

    def test_identify_threats_phase(self, adapter, sample_cve):
        """Test Phase 3: Identify Threats."""
        assessment = adapter.assess_risk(cve=sample_cve)

        threats = assessment["phases"]["identify_threats"]
        assert "scenarios" in threats
        assert "total_scenarios" in threats
        assert threats["total_scenarios"] >= 1

    def test_threat_scenarios_with_cve(self, adapter, sample_cve):
        """Test threat scenarios include CVE exploitation."""
        assessment = adapter.assess_risk(cve=sample_cve)

        scenarios = assessment["phases"]["identify_threats"]["scenarios"]
        cve_scenario = next(
            (s for s in scenarios if sample_cve["id"] in s.get("scenario_id", "")),
            None
        )

        assert cve_scenario is not None
        assert "probability" in cve_scenario

    def test_insider_threat_scenario(self, adapter):
        """Test that insider threat scenario is included."""
        assessment = adapter.assess_risk()

        scenarios = assessment["phases"]["identify_threats"]["scenarios"]
        insider = next(
            (s for s in scenarios if "insider" in s["title"].lower()), None
        )

        assert insider is not None

    def test_external_threat_scenario(self, adapter):
        """Test that external threat scenario is included."""
        assessment = adapter.assess_risk()

        scenarios = assessment["phases"]["identify_threats"]["scenarios"]
        external = next(
            (s for s in scenarios if "external" in s["title"].lower()), None
        )

        assert external is not None

    def test_risk_analysis_calculation(self, adapter, sample_asset, sample_cve):
        """Test risk analysis calculation."""
        assessment = adapter.assess_risk(cve=sample_cve, asset=sample_asset)

        risk_analysis = assessment["risk_analysis"]
        assert "overall_risk_score" in risk_analysis
        assert "impact_scores" in risk_analysis
        assert "probability_score" in risk_analysis

    def test_impact_areas(self, adapter):
        """Test multiple impact areas assessment."""
        context = {
            "impact_areas": ["reputation", "financial", "productivity"]
        }
        assessment = adapter.assess_risk(context=context)

        impact_scores = assessment["risk_analysis"]["impact_scores"]
        assert len(impact_scores) == 3

    def test_security_requirements_high_criticality(self, adapter):
        """Test security requirements for high criticality assets."""
        asset = {"criticality": "high"}
        assessment = adapter.assess_risk(asset=asset)

        sec_req = assessment["phases"]["profile_assets"]["security_requirements"]
        assert sec_req["confidentiality"] == "High"
        assert sec_req["integrity"] == "High"
        assert sec_req["availability"] == "High"

    def test_recommendations(self, adapter, sample_cve):
        """Test recommendations generation."""
        assessment = adapter.assess_risk(cve=sample_cve)

        assert "recommendations" in assessment
        assert len(assessment["recommendations"]) > 0


class TestISO31000Adapter:
    """Test suite for ISO 31000:2018 Adapter."""

    @pytest.fixture
    def adapter(self):
        """Create ISO 31000 adapter instance."""
        return ISO31000Adapter()

    @pytest.fixture
    def sample_cve(self):
        """Create sample CVE data."""
        return {
            "id": "CVE-2024-7890",
            "cvss_score": 6.5,
            "description": "Authentication bypass",
        }

    @pytest.fixture
    def sample_asset(self):
        """Create sample asset data."""
        return {
            "id": "ASSET-003",
            "name": "Authentication Server",
            "criticality": "high",
        }

    def test_init_default(self):
        """Test adapter initialization with default risk appetite."""
        adapter = ISO31000Adapter()

        assert adapter.risk_appetite == "moderate"

    def test_init_custom_risk_appetite(self):
        """Test adapter initialization with custom risk appetite."""
        adapter = ISO31000Adapter(risk_appetite="conservative")

        assert adapter.risk_appetite == "conservative"

    def test_assess_risk_basic(self, adapter):
        """Test basic ISO 31000 risk assessment."""
        assessment = adapter.assess_risk()

        assert assessment["framework"] == "ISO 31000:2018"
        assert "overall_score" in assessment
        assert "risk_level" in assessment

    def test_four_step_process(self, adapter):
        """Test that all four ISO 31000 steps are included."""
        assessment = adapter.assess_risk()

        assert "risk_identification" in assessment
        assert "risk_analysis" in assessment
        assert "risk_evaluation" in assessment
        assert "risk_treatment" in assessment

    def test_risk_identification(self, adapter, sample_cve):
        """Test Step 1: Risk Identification."""
        assessment = adapter.assess_risk(cve=sample_cve)

        identification = assessment["risk_identification"]
        assert "risk_event" in identification
        assert "risk_source" in identification
        assert "risk_causes" in identification
        assert sample_cve["id"] in identification["risk_event"]

    def test_risk_analysis_5x5_matrix(self, adapter):
        """Test Step 2: Risk Analysis with 5x5 matrix."""
        assessment = adapter.assess_risk()

        analysis = assessment["risk_analysis"]
        assert "likelihood_level" in analysis
        assert "consequence_level" in analysis
        assert 1 <= analysis["likelihood_level"] <= 5
        assert 1 <= analysis["consequence_level"] <= 5

    def test_risk_matrix_calculation(self, adapter):
        """Test risk matrix rating calculation."""
        # Test a few matrix calculations
        assert adapter.RISK_MATRIX[(1, 1)] == 1
        assert adapter.RISK_MATRIX[(5, 5)] == 25
        assert adapter.RISK_MATRIX[(3, 3)] == 9

    def test_inherent_vs_residual_risk(self, adapter):
        """Test inherent vs residual risk calculation."""
        context_no_controls = {"has_controls": False}
        context_with_controls = {"has_controls": True, "control_effectiveness": "high"}

        assessment_no_controls = adapter.assess_risk(context=context_no_controls)
        assessment_with_controls = adapter.assess_risk(context=context_with_controls)

        inherent_1 = assessment_no_controls["risk_analysis"]["inherent_risk_rating"]
        residual_1 = assessment_no_controls["risk_analysis"]["residual_risk_rating"]

        residual_2 = assessment_with_controls["risk_analysis"]["residual_risk_rating"]

        assert inherent_1 == residual_1  # No controls = same risk
        assert residual_2 < inherent_1  # Controls reduce risk

    def test_likelihood_assessment_high_cvss(self, adapter):
        """Test likelihood assessment with high CVSS."""
        cve_high = {"cvss_score": 9.5}
        assessment = adapter.assess_risk(cve=cve_high)

        assert assessment["risk_analysis"]["likelihood_level"] >= 4

    def test_consequence_assessment_critical_asset(self, adapter):
        """Test consequence assessment for critical asset."""
        asset = {"criticality": "critical"}
        assessment = adapter.assess_risk(asset=asset)

        assert assessment["risk_analysis"]["consequence_level"] >= 3

    def test_risk_evaluation_acceptance(self, adapter):
        """Test Step 3: Risk Evaluation."""
        assessment = adapter.assess_risk()

        evaluation = assessment["risk_evaluation"]
        assert "is_acceptable" in evaluation
        assert "requires_treatment" in evaluation
        assert "priority" in evaluation

    def test_risk_appetite_conservative(self):
        """Test risk evaluation with conservative appetite."""
        adapter = ISO31000Adapter(risk_appetite="conservative")
        assessment = adapter.assess_risk()

        assert adapter._get_acceptance_threshold() == 4

    def test_risk_appetite_aggressive(self):
        """Test risk evaluation with aggressive appetite."""
        adapter = ISO31000Adapter(risk_appetite="aggressive")
        assessment = adapter.assess_risk()

        assert adapter._get_acceptance_threshold() == 15

    def test_risk_treatment_options(self, adapter):
        """Test Step 4: Risk Treatment."""
        assessment = adapter.assess_risk()

        treatment = assessment["risk_treatment"]
        assert "primary_treatment" in treatment
        assert "treatment_options" in treatment
        assert len(treatment["treatment_options"]) > 0

    def test_treatment_for_high_risk(self, adapter):
        """Test treatment recommendation for high risk."""
        cve = {"cvss_score": 9.0}
        asset = {"criticality": "critical"}

        assessment = adapter.assess_risk(cve=cve, asset=asset)

        treatment = assessment["risk_treatment"]
        assert treatment["primary_treatment"] in ["reduce", "avoid"]

    def test_treatment_for_low_risk(self, adapter):
        """Test treatment recommendation for low risk."""
        context = {"has_controls": True, "control_effectiveness": "high"}
        cve = {"cvss_score": 3.0}

        assessment = adapter.assess_risk(cve=cve, context=context)

        treatment = assessment["risk_treatment"]
        # Low residual risk might be acceptable
        assert treatment["primary_treatment"] in ["accept", "reduce"]

    def test_control_effectiveness_calculation(self, adapter):
        """Test control effectiveness percentage."""
        effectiveness = adapter._calculate_control_effectiveness(
            inherent_rating=20, residual_rating=10
        )

        assert effectiveness == 0.5  # 50% reduction

    def test_matrix_to_score_conversion(self, adapter):
        """Test conversion of matrix rating to 0-10 score."""
        score_low = adapter._matrix_to_score(5)
        score_high = adapter._matrix_to_score(25)

        assert score_low == 2.0
        assert score_high == 10.0

    def test_risk_level_categories(self, adapter):
        """Test risk level categorization."""
        assert adapter._rating_to_level(2) == "Low"
        assert adapter._rating_to_level(7) == "Medium"
        assert adapter._rating_to_level(12) == "High"
        assert adapter._rating_to_level(20) == "Critical"

    def test_recommendations_generation(self, adapter):
        """Test recommendations generation."""
        assessment = adapter.assess_risk()

        assert "recommendations" in assessment
        assert len(assessment["recommendations"]) > 0
