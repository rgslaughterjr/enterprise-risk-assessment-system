"""Tests for control processing tools (Deduplicator, Matcher, Gap Analyzer).

Comprehensive test suite covering:
- Control deduplication with TF-IDF
- Control-risk matching
- Gap analysis and prioritization
- Edge cases and error handling
"""

import pytest
import numpy as np

from src.tools.control_deduplicator import ControlDeduplicator
from src.tools.control_risk_matcher import ControlRiskMatcher
from src.tools.gap_analyzer import GapAnalyzer


# ==============================================================================
# Control Deduplicator Tests (15+ tests)
# ==============================================================================

class TestControlDeduplicator:
    """Test suite for control deduplicator."""

    def test_init(self):
        """Test deduplicator initialization."""
        dedup = ControlDeduplicator(similarity_threshold=0.85)
        assert dedup.similarity_threshold == 0.85
        assert dedup.vectorizer is not None

    def test_deduplicate_empty_list(self):
        """Test deduplicating empty list."""
        dedup = ControlDeduplicator()
        result = dedup.deduplicate_controls([])

        assert isinstance(result, list)
        assert len(result) == 0

    def test_deduplicate_single_control(self):
        """Test deduplicating single control."""
        dedup = ControlDeduplicator()
        controls = [
            {"id": "NIST-AC-1", "title": "Access Control Policy", "description": "Policy"}
        ]

        result = dedup.deduplicate_controls(controls)

        assert len(result) == 1
        assert result[0]["id"] == "NIST-AC-1"

    def test_deduplicate_identical_controls(self):
        """Test deduplicating identical controls from different sources."""
        dedup = ControlDeduplicator()
        controls = [
            {"id": "NIST-AC-1", "title": "Access Control", "description": "Policy", "source": "confluence"},
            {"id": "NIST-AC-1", "title": "Access Control", "description": "Policy", "source": "servicenow"},
        ]

        result = dedup.deduplicate_controls(controls)

        assert len(result) == 1
        assert "sources" in result[0]
        assert len(result[0]["sources"]) == 2

    def test_deduplicate_different_controls(self):
        """Test deduplicating completely different controls."""
        dedup = ControlDeduplicator()
        controls = [
            {"id": "NIST-AC-1", "title": "Access Control", "description": "Access policy"},
            {"id": "NIST-AU-2", "title": "Audit Events", "description": "Logging events"},
        ]

        result = dedup.deduplicate_controls(controls)

        assert len(result) == 2

    def test_group_by_id(self):
        """Test grouping controls by ID."""
        dedup = ControlDeduplicator()
        controls = [
            {"id": "NIST-AC-1", "source": "confluence"},
            {"id": "NIST-AC-1", "source": "servicenow"},
            {"id": "NIST-AU-2", "source": "filesystem"},
        ]

        groups = dedup._group_by_id(controls)

        assert len(groups) == 2
        assert len(groups["NIST-AC-1"]) == 2
        assert len(groups["NIST-AU-2"]) == 1

    def test_prepare_control_text(self):
        """Test preparing control text for vectorization."""
        dedup = ControlDeduplicator()
        control = {
            "title": "Access Control",
            "description": "Establish access policies",
            "framework": "NIST SP 800-53",
        }

        text = dedup._prepare_control_text(control)

        assert "Access Control" in text
        assert "access policies" in text.lower()

    def test_find_similar_controls(self):
        """Test finding similar controls."""
        dedup = ControlDeduplicator()

        reference = {
            "id": "CTRL-1",
            "title": "Access Control Policy",
            "description": "Establish and maintain access control policies"
        }

        candidates = [
            {"id": "CTRL-2", "title": "Access Control", "description": "Access policies"},
            {"id": "CTRL-3", "title": "Audit Logging", "description": "Log all events"},
        ]

        similar = dedup.find_similar_controls(reference, candidates, threshold=0.3)

        assert isinstance(similar, list)
        assert len(similar) > 0
        assert all(isinstance(item, tuple) and len(item) == 2 for item in similar)

    def test_merge_duplicate_controls(self):
        """Test merging duplicate controls."""
        dedup = ControlDeduplicator()
        duplicates = [
            {
                "id": "NIST-AC-1",
                "title": "Access Control",
                "description": "Short description",
                "source": "confluence",
                "effectiveness_score": 80,
            },
            {
                "id": "NIST-AC-1",
                "title": "Access Control Policy",
                "description": "Longer and more detailed description",
                "source": "servicenow",
                "effectiveness_score": 90,
            },
        ]

        merged = dedup.merge_duplicate_controls(duplicates)

        assert merged["id"] == "NIST-AC-1"
        assert "sources" in merged
        assert set(merged["sources"]) == {"confluence", "servicenow"}
        assert len(merged["description"]) > len("Short description")

    def test_merge_empty_group(self):
        """Test merging empty control group."""
        dedup = ControlDeduplicator()
        merged = dedup.merge_duplicate_controls([])

        assert merged == {}

    def test_merge_single_control(self):
        """Test merging single control returns same control."""
        dedup = ControlDeduplicator()
        control = {"id": "CTRL-1", "title": "Test"}

        merged = dedup.merge_duplicate_controls([control])

        assert merged == control

    def test_merge_effectiveness_scores(self):
        """Test effectiveness scores are averaged when merging."""
        dedup = ControlDeduplicator()
        duplicates = [
            {"id": "CTRL-1", "effectiveness_score": 80},
            {"id": "CTRL-1", "effectiveness_score": 90},
        ]

        merged = dedup.merge_duplicate_controls(duplicates)

        assert "effectiveness_score" in merged
        assert merged["effectiveness_score"] == 85.0

    def test_get_deduplication_stats(self):
        """Test deduplication statistics calculation."""
        dedup = ControlDeduplicator()

        deduplicated = [
            {"id": "CTRL-1", "sources": ["confluence", "servicenow"], "source_count": 2},
            {"id": "CTRL-2", "sources": ["filesystem"], "source_count": 1},
        ]

        stats = dedup.get_deduplication_stats(5, deduplicated)

        assert stats["original_count"] == 5
        assert stats["unique_count"] == 2
        assert stats["duplicates_removed"] == 3
        assert stats["deduplication_rate"] == 60.0

    def test_similarity_threshold_customization(self):
        """Test custom similarity threshold."""
        dedup = ControlDeduplicator(similarity_threshold=0.5)

        controls = [
            {"id": "UNKNOWN", "title": "Access Control", "description": "Access"},
            {"id": "UNKNOWN", "title": "Access Management", "description": "Management"},
        ]

        result = dedup.deduplicate_controls(controls, threshold=0.9)

        # Higher threshold = less aggressive deduplication
        assert len(result) >= 1


# ==============================================================================
# Control-Risk Matcher Tests (15+ tests)
# ==============================================================================

class TestControlRiskMatcher:
    """Test suite for control-risk matcher."""

    def test_init(self):
        """Test matcher initialization."""
        matcher = ControlRiskMatcher(use_llm=False, similarity_threshold=0.3)
        assert matcher.use_llm is False
        assert matcher.similarity_threshold == 0.3

    def test_match_empty_controls(self):
        """Test matching with empty controls list."""
        matcher = ControlRiskMatcher()
        risks = [{"id": "RISK-1", "title": "Unauthorized Access"}]

        mappings = matcher.match_controls_to_risks([], risks)

        assert isinstance(mappings, list)
        assert len(mappings) == 0

    def test_match_empty_risks(self):
        """Test matching with empty risks list."""
        matcher = ControlRiskMatcher()
        controls = [{"id": "CTRL-1", "title": "Access Control"}]

        mappings = matcher.match_controls_to_risks(controls, [])

        assert isinstance(mappings, list)
        assert len(mappings) == 0

    def test_match_by_category(self):
        """Test category-based matching."""
        matcher = ControlRiskMatcher()

        controls = [
            {"id": "CTRL-1", "title": "Access Control", "category": "Access Control"}
        ]

        risks = [
            {"id": "RISK-1", "title": "Unauthorized Access", "description": "Unauthorized access risk"}
        ]

        mappings = matcher.match_controls_to_risks(controls, risks)

        assert len(mappings) > 0
        assert any(m["match_method"] in ["category_mapping", "text_similarity", "keyword_heuristic"] for m in mappings)

    def test_match_metadata_populated(self):
        """Test mapping metadata is correctly populated."""
        matcher = ControlRiskMatcher()

        controls = [{"id": "CTRL-1", "title": "Access Control", "framework": "NIST"}]
        risks = [{"id": "RISK-1", "title": "Access Risk", "risk_level": "High"}]

        mappings = matcher.match_controls_to_risks(controls, risks)

        if mappings:
            mapping = mappings[0]
            assert "control_id" in mapping
            assert "risk_id" in mapping
            assert "match_score" in mapping
            assert "match_method" in mapping

    def test_calculate_coverage_score_no_controls(self):
        """Test coverage score with no controls."""
        matcher = ControlRiskMatcher()
        risk = {"id": "RISK-1"}

        score = matcher.calculate_coverage_score(risk, [])

        assert score == 0.0

    def test_calculate_coverage_score_with_controls(self):
        """Test coverage score with controls."""
        matcher = ControlRiskMatcher()
        risk = {"id": "RISK-1"}
        controls = [
            {"id": "CTRL-1", "implementation_status": "Implemented", "effectiveness_score": 0.85},
            {"id": "CTRL-2", "implementation_status": "Implemented", "effectiveness_score": 0.90},
        ]

        score = matcher.calculate_coverage_score(risk, controls)

        assert 0.0 <= score <= 1.0
        assert score > 0.5  # Should be well-covered

    def test_identify_control_gaps(self):
        """Test identifying control gaps."""
        matcher = ControlRiskMatcher()

        risks = [
            {"id": "RISK-1", "title": "High Risk", "risk_level": "High"},
            {"id": "RISK-2", "title": "Low Risk", "risk_level": "Low"},
        ]

        controls = [
            {"id": "CTRL-1", "title": "Control", "implementation_status": "Implemented"}
        ]

        gaps = matcher.identify_control_gaps(risks, controls)

        assert isinstance(gaps, list)
        # Some risks may have gaps

    def test_gap_metadata(self):
        """Test gap metadata includes all required fields."""
        matcher = ControlRiskMatcher()

        risks = [{"id": "RISK-1", "title": "Risk", "risk_level": "Critical"}]
        controls = []  # No controls = guaranteed gap

        gaps = matcher.identify_control_gaps(risks, controls)

        assert len(gaps) > 0
        gap = gaps[0]
        assert "risk_id" in gap
        assert "risk_level" in gap
        assert "coverage_score" in gap
        assert "gap_severity" in gap

    def test_prepare_control_text(self):
        """Test control text preparation."""
        matcher = ControlRiskMatcher()
        control = {
            "title": "Access Control",
            "description": "Control access to systems",
            "category": "Access Control",
        }

        text = matcher._prepare_control_text(control)

        assert "Access Control" in text
        assert "Control access" in text

    def test_prepare_risk_text(self):
        """Test risk text preparation."""
        matcher = ControlRiskMatcher()
        risk = {
            "title": "Unauthorized Access",
            "description": "Risk of unauthorized access",
            "threat": "External attacker",
        }

        text = matcher._prepare_risk_text(risk)

        assert "Unauthorized Access" in text
        assert "External attacker" in text

    def test_extract_keywords(self):
        """Test keyword extraction."""
        matcher = ControlRiskMatcher()
        text = "access control authentication encryption password"

        keywords = matcher._extract_keywords(text)

        assert isinstance(keywords, list)
        assert "access" in keywords
        assert "authentication" in keywords

    def test_severity_priority(self):
        """Test severity priority ordering."""
        matcher = ControlRiskMatcher()

        assert matcher._severity_priority("Critical") < matcher._severity_priority("High")
        assert matcher._severity_priority("High") < matcher._severity_priority("Medium")
        assert matcher._severity_priority("Medium") < matcher._severity_priority("Low")


# ==============================================================================
# Gap Analyzer Tests (15+ tests)
# ==============================================================================

class TestGapAnalyzer:
    """Test suite for gap analyzer."""

    def test_init(self):
        """Test analyzer initialization."""
        analyzer = GapAnalyzer()
        assert analyzer is not None

    def test_analyze_gaps_empty_risks(self):
        """Test gap analysis with empty risks."""
        analyzer = GapAnalyzer()
        analysis = analyzer.analyze_gaps([], [])

        assert isinstance(analysis, dict)
        assert "summary" in analysis

    def test_analyze_gaps_no_controls(self):
        """Test gap analysis with risks but no controls."""
        analyzer = GapAnalyzer()

        risks = [
            {"id": "RISK-1", "title": "High Risk", "risk_level": "High", "description": "Risk"}
        ]

        analysis = analyzer.analyze_gaps(risks, [])

        assert len(analysis["gaps"]) > 0
        assert analysis["gaps"][0]["coverage_score"] == 0.0

    def test_analyze_gaps_with_controls(self):
        """Test gap analysis with controls."""
        analyzer = GapAnalyzer()

        risks = [
            {"id": "RISK-1", "title": "Risk", "risk_level": "Medium"}
        ]

        controls = [
            {"id": "CTRL-1", "title": "Control", "implementation_status": "Implemented", "effectiveness_score": 0.9}
        ]

        # Need mappings
        from src.tools.control_risk_matcher import ControlRiskMatcher
        matcher = ControlRiskMatcher()
        mappings = matcher.match_controls_to_risks(controls, risks)

        analysis = analyzer.analyze_gaps(risks, controls, mappings)

        assert "gaps" in analysis
        assert "covered_risks" in analysis
        assert "summary" in analysis

    def test_calculate_coverage_score(self):
        """Test coverage score calculation."""
        analyzer = GapAnalyzer()

        risk = {"id": "RISK-1"}
        controls = [
            {"id": "CTRL-1", "implementation_status": "Implemented", "effectiveness_score": 85},
        ]

        score = analyzer._calculate_coverage_score(risk, controls)

        assert 0.0 <= score <= 1.0

    def test_calculate_residual_risk(self):
        """Test residual risk calculation."""
        analyzer = GapAnalyzer()

        risk = {"id": "RISK-1", "risk_level": "High"}
        controls = []
        coverage = 0.0

        residual = analyzer._calculate_residual_risk(risk, controls, coverage)

        assert residual in ["Critical", "High", "Medium", "Low", "Minimal"]
        # High risk + no coverage = High/Critical residual
        assert residual in ["Critical", "High"]

    def test_determine_gap_category(self):
        """Test gap category determination."""
        analyzer = GapAnalyzer()

        # No controls = Missing Control
        category = analyzer._determine_gap_category([], 0.0)
        assert category == analyzer.CATEGORY_MISSING_CONTROL

        # Partial implementation
        controls = [{"implementation_status": "Partially Implemented"}]
        category = analyzer._determine_gap_category(controls, 0.5)
        assert category == analyzer.CATEGORY_PARTIAL_IMPLEMENTATION

    def test_prioritize_gaps(self):
        """Test gap prioritization."""
        analyzer = GapAnalyzer()

        gaps = [
            {"risk_id": "RISK-1", "risk_level": "High", "coverage_score": 0.2},
            {"risk_id": "RISK-2", "risk_level": "Low", "coverage_score": 0.8},
        ]

        prioritized = analyzer.prioritize_gaps(gaps)

        assert len(prioritized) == 2
        assert all("priority" in g for g in prioritized)
        # High risk + low coverage should be higher priority
        assert prioritized[0]["risk_id"] == "RISK-1"

    def test_priority_levels(self):
        """Test all priority levels are assigned correctly."""
        analyzer = GapAnalyzer()

        # Critical priority
        gap = {"risk_level": "Critical", "coverage_score": 0.1}
        priority = analyzer._calculate_priority(gap, ["risk_level", "coverage_score"])
        assert priority in [analyzer.PRIORITY_CRITICAL, analyzer.PRIORITY_HIGH]

        # Low priority
        gap = {"risk_level": "Low", "coverage_score": 0.9}
        priority = analyzer._calculate_priority(gap, ["risk_level", "coverage_score"])
        assert priority in [analyzer.PRIORITY_LOW, analyzer.PRIORITY_MEDIUM]

    def test_generate_recommendations(self):
        """Test recommendation generation."""
        analyzer = GapAnalyzer()

        gaps = [
            {
                "risk_id": "RISK-1",
                "risk_name": "High Risk",
                "gap_category": analyzer.CATEGORY_MISSING_CONTROL,
                "priority": analyzer.PRIORITY_HIGH,
                "coverage_score": 0.0,
            }
        ]

        recommendations = analyzer.generate_recommendations(gaps)

        assert len(recommendations) == 1
        rec = recommendations[0]
        assert "action" in rec
        assert "details" in rec
        assert "estimated_effort" in rec
        assert "recommended_timeline" in rec

    def test_recommendation_fields(self):
        """Test recommendation contains all required fields."""
        analyzer = GapAnalyzer()

        gaps = [
            {
                "risk_id": "RISK-1",
                "risk_name": "Test Risk",
                "gap_category": analyzer.CATEGORY_PARTIAL_IMPLEMENTATION,
                "priority": analyzer.PRIORITY_MEDIUM,
                "coverage_score": 0.3,
            }
        ]

        recs = analyzer.generate_recommendations(gaps)

        assert len(recs) > 0
        rec = recs[0]
        required_fields = ["risk_id", "priority", "action", "details", "estimated_effort", "recommended_timeline"]
        for field in required_fields:
            assert field in rec

    def test_effort_timeline_estimation(self):
        """Test effort and timeline estimation."""
        analyzer = GapAnalyzer()

        # Critical priority = immediate timeline
        effort, timeline = analyzer._estimate_effort_timeline(
            analyzer.PRIORITY_CRITICAL,
            {"gap_category": analyzer.CATEGORY_MISSING_CONTROL}
        )

        assert effort in ["Low", "Medium", "High"]
        assert "week" in timeline.lower() or "month" in timeline.lower()

    def test_calculate_summary_stats(self):
        """Test summary statistics calculation."""
        analyzer = GapAnalyzer()

        risks = [{"id": f"RISK-{i}"} for i in range(10)]
        controls = [{"id": f"CTRL-{i}"} for i in range(5)]
        gaps = [{"coverage_score": 0.3}, {"coverage_score": 0.4}]
        covered = [{"coverage_score": 0.8}, {"coverage_score": 0.9}]

        summary = analyzer._calculate_summary_stats(risks, controls, gaps, covered)

        assert summary["total_risks"] == 10
        assert summary["total_controls"] == 5
        assert summary["gaps_identified"] == 2
        assert summary["adequately_covered"] == 2
        assert "coverage_rate" in summary
        assert "average_coverage_score" in summary

    def test_is_low_effectiveness(self):
        """Test low effectiveness detection."""
        analyzer = GapAnalyzer()

        # Low effectiveness (< 50%)
        control = {"effectiveness_score": 40}
        assert analyzer._is_low_effectiveness(control) is True

        # High effectiveness
        control = {"effectiveness_score": 85}
        assert analyzer._is_low_effectiveness(control) is False

        # Normalized score
        control = {"effectiveness_score": 0.4}
        assert analyzer._is_low_effectiveness(control) is True
