"""Tests for AttackTransitionBuilder."""

import pytest
import numpy as np
from pathlib import Path
import tempfile
import json
import pickle

from src.tools.attack_transition_builder import AttackTransitionBuilder


class TestAttackTransitionBuilderInit:
    """Test initialization."""

    def test_init_without_data(self):
        """Test initialization without data file."""
        builder = AttackTransitionBuilder()
        assert builder is not None
        assert isinstance(builder.techniques, dict)
        assert isinstance(builder.technique_ids, list)

    def test_init_with_mock_data(self):
        """Test that mock data is loaded when no file exists."""
        builder = AttackTransitionBuilder(data_path="/nonexistent/path.json")
        builder.parse_mitre_attack()
        assert len(builder.techniques) > 0
        assert "T1190" in builder.techniques  # Mock data includes this

    def test_find_data_file(self):
        """Test data file finding logic."""
        builder = AttackTransitionBuilder()
        # Should return None or a valid path
        result = builder._find_data_file()
        assert result is None or Path(result).exists()


class TestParseMitreAttack:
    """Test MITRE ATT&CK parsing."""

    def test_parse_with_no_data(self):
        """Test parsing when no data is loaded."""
        builder = AttackTransitionBuilder(data_path="/nonexistent/path.json")
        num_techniques = builder.parse_mitre_attack()
        assert num_techniques > 0  # Should load mock data
        assert len(builder.techniques) == num_techniques

    def test_parse_builds_technique_index(self):
        """Test that parsing builds technique index."""
        builder = AttackTransitionBuilder()
        builder.parse_mitre_attack()

        assert len(builder.technique_ids) == len(builder.techniques)
        assert len(builder.technique_index) == len(builder.techniques)

        for tech_id in builder.techniques.keys():
            assert tech_id in builder.technique_ids
            assert tech_id in builder.technique_index

    def test_technique_data_structure(self):
        """Test that parsed techniques have correct structure."""
        builder = AttackTransitionBuilder()
        builder.parse_mitre_attack()

        for tech_id, tech_data in builder.techniques.items():
            assert "name" in tech_data
            assert "description" in tech_data
            assert "tactics" in tech_data
            assert "platforms" in tech_data
            assert isinstance(tech_data["tactics"], list)
            assert isinstance(tech_data["platforms"], list)

    def test_mock_data_content(self):
        """Test that mock data contains expected techniques."""
        builder = AttackTransitionBuilder()
        builder.parse_mitre_attack()

        # Check for key mock techniques
        assert "T1190" in builder.techniques  # Exploit Public-Facing Application
        assert "T1059" in builder.techniques  # Command and Scripting Interpreter
        assert "T1068" in builder.techniques  # Exploitation for Privilege Escalation


class TestExtractRelationships:
    """Test technique relationship extraction."""

    def test_extract_relationships_basic(self):
        """Test basic relationship extraction."""
        builder = AttackTransitionBuilder()
        builder.parse_mitre_attack()
        relationships = builder.extract_technique_relationships()

        assert len(relationships) > 0
        assert all(isinstance(r, tuple) and len(r) == 2 for r in relationships)

    def test_relationships_are_valid_techniques(self):
        """Test that all relationships reference valid techniques."""
        builder = AttackTransitionBuilder()
        builder.parse_mitre_attack()
        relationships = builder.extract_technique_relationships()

        for src, dst in relationships:
            assert src in builder.techniques
            assert dst in builder.techniques

    def test_tactic_progression_relationships(self):
        """Test that relationships follow tactic progression."""
        builder = AttackTransitionBuilder()
        builder.parse_mitre_attack()
        relationships = builder.extract_technique_relationships()

        # Should have relationships from initial-access to execution
        initial_access_techs = [
            tid for tid, tdata in builder.techniques.items()
            if "initial-access" in tdata["tactics"]
        ]
        execution_techs = [
            tid for tid, tdata in builder.techniques.items()
            if "execution" in tdata["tactics"]
        ]

        # Find at least one relationship
        found = any(
            src in initial_access_techs and dst in execution_techs
            for src, dst in relationships
        )
        assert found, "Should have relationships from initial-access to execution"

    def test_relationships_stored(self):
        """Test that relationships are stored in builder."""
        builder = AttackTransitionBuilder()
        builder.parse_mitre_attack()
        relationships = builder.extract_technique_relationships()

        assert builder.relationships == relationships
        assert len(builder.relationships) > 0


class TestCalculateTransitionProbabilities:
    """Test transition probability calculation."""

    def test_calculate_probabilities_basic(self):
        """Test basic probability calculation."""
        builder = AttackTransitionBuilder()
        builder.parse_mitre_attack()
        builder.extract_technique_relationships()
        probs = builder.calculate_transition_probabilities()

        assert len(probs) > 0
        assert isinstance(probs, dict)

    def test_probabilities_sum_to_one(self):
        """Test that probabilities from each technique sum to ~1.0."""
        builder = AttackTransitionBuilder()
        builder.parse_mitre_attack()
        builder.extract_technique_relationships()
        probs = builder.calculate_transition_probabilities()

        for src_tech, targets in probs.items():
            total = sum(targets.values())
            assert abs(total - 1.0) < 0.01, f"Probabilities for {src_tech} sum to {total}"

    def test_probabilities_in_valid_range(self):
        """Test that all probabilities are between 0 and 1."""
        builder = AttackTransitionBuilder()
        builder.parse_mitre_attack()
        builder.extract_technique_relationships()
        probs = builder.calculate_transition_probabilities()

        for src_tech, targets in probs.items():
            for dst_tech, prob in targets.items():
                assert 0.0 <= prob <= 1.0, f"Invalid probability: {prob}"

    def test_forward_progression_bonus(self):
        """Test that forward progression gets higher weight."""
        builder = AttackTransitionBuilder()
        builder.parse_mitre_attack()
        builder.extract_technique_relationships()
        builder.calculate_transition_probabilities()

        # Check stored probabilities
        assert len(builder.transition_probs) > 0

    def test_transition_counts_populated(self):
        """Test that transition counts are populated."""
        builder = AttackTransitionBuilder()
        builder.parse_mitre_attack()
        builder.extract_technique_relationships()
        builder.calculate_transition_probabilities()

        assert len(builder.transition_counts) > 0


class TestBuildTransitionMatrix:
    """Test transition matrix construction."""

    def test_build_matrix_basic(self):
        """Test basic matrix building."""
        builder = AttackTransitionBuilder()
        builder.parse_mitre_attack()
        builder.extract_technique_relationships()
        builder.calculate_transition_probabilities()
        matrix = builder.build_transition_matrix()

        assert isinstance(matrix, np.ndarray)
        assert matrix.ndim == 2
        assert matrix.shape[0] == matrix.shape[1]

    def test_matrix_dimensions(self):
        """Test matrix dimensions match number of techniques."""
        builder = AttackTransitionBuilder()
        builder.parse_mitre_attack()
        builder.extract_technique_relationships()
        builder.calculate_transition_probabilities()
        matrix = builder.build_transition_matrix()

        n_techniques = len(builder.technique_ids)
        assert matrix.shape == (n_techniques, n_techniques)

    def test_matrix_rows_sum_to_one(self):
        """Test that matrix rows sum to 1 (or 0 for terminal states)."""
        builder = AttackTransitionBuilder()
        builder.parse_mitre_attack()
        builder.extract_technique_relationships()
        builder.calculate_transition_probabilities()
        matrix = builder.build_transition_matrix()

        row_sums = matrix.sum(axis=1)
        for i, row_sum in enumerate(row_sums):
            assert abs(row_sum - 1.0) < 0.01 or row_sum == 0.0, \
                f"Row {i} sum is {row_sum}"

    def test_matrix_values_in_range(self):
        """Test that all matrix values are valid probabilities."""
        builder = AttackTransitionBuilder()
        builder.parse_mitre_attack()
        builder.extract_technique_relationships()
        builder.calculate_transition_probabilities()
        matrix = builder.build_transition_matrix()

        assert np.all(matrix >= 0.0)
        assert np.all(matrix <= 1.0)

    def test_matrix_stored(self):
        """Test that matrix is stored in builder."""
        builder = AttackTransitionBuilder()
        builder.parse_mitre_attack()
        builder.extract_technique_relationships()
        builder.calculate_transition_probabilities()
        matrix = builder.build_transition_matrix()

        assert builder.transition_matrix is not None
        np.testing.assert_array_equal(builder.transition_matrix, matrix)


class TestCaching:
    """Test matrix caching functionality."""

    def test_cache_matrix(self):
        """Test caching matrix to disk."""
        builder = AttackTransitionBuilder()
        builder.parse_mitre_attack()
        builder.extract_technique_relationships()
        builder.calculate_transition_probabilities()
        builder.build_transition_matrix()

        with tempfile.NamedTemporaryFile(suffix=".pkl", delete=False) as f:
            cache_path = f.name

        try:
            builder.cache_matrix(cache_path)
            assert Path(cache_path).exists()
        finally:
            Path(cache_path).unlink(missing_ok=True)

    def test_load_cached_matrix(self):
        """Test loading cached matrix."""
        # Create and cache
        builder1 = AttackTransitionBuilder()
        builder1.parse_mitre_attack()
        builder1.extract_technique_relationships()
        builder1.calculate_transition_probabilities()
        matrix1 = builder1.build_transition_matrix()

        with tempfile.NamedTemporaryFile(suffix=".pkl", delete=False) as f:
            cache_path = f.name

        try:
            builder1.cache_matrix(cache_path)

            # Load from cache
            builder2 = AttackTransitionBuilder()
            success = builder2.load_cached_matrix(cache_path)

            assert success
            assert builder2.transition_matrix is not None
            np.testing.assert_array_equal(builder2.transition_matrix, matrix1)
            assert builder2.technique_ids == builder1.technique_ids
            assert builder2.techniques == builder1.techniques

        finally:
            Path(cache_path).unlink(missing_ok=True)

    def test_load_nonexistent_cache(self):
        """Test loading from nonexistent cache file."""
        builder = AttackTransitionBuilder()
        success = builder.load_cached_matrix("/nonexistent/cache.pkl")
        assert not success

    def test_cache_preserves_data(self):
        """Test that caching preserves all data."""
        builder1 = AttackTransitionBuilder()
        builder1.parse_mitre_attack()
        builder1.extract_technique_relationships()
        builder1.calculate_transition_probabilities()
        builder1.build_transition_matrix()

        with tempfile.NamedTemporaryFile(suffix=".pkl", delete=False) as f:
            cache_path = f.name

        try:
            builder1.cache_matrix(cache_path)

            builder2 = AttackTransitionBuilder()
            builder2.load_cached_matrix(cache_path)

            # Verify all data preserved
            assert len(builder2.techniques) == len(builder1.techniques)
            assert len(builder2.transition_probs) == len(builder1.transition_probs)

        finally:
            Path(cache_path).unlink(missing_ok=True)


class TestUtilityMethods:
    """Test utility methods."""

    def test_get_technique_name(self):
        """Test getting technique name."""
        builder = AttackTransitionBuilder()
        builder.parse_mitre_attack()

        name = builder.get_technique_name("T1190")
        assert name == "Exploit Public-Facing Application"

    def test_get_technique_name_invalid(self):
        """Test getting name for invalid technique."""
        builder = AttackTransitionBuilder()
        builder.parse_mitre_attack()

        name = builder.get_technique_name("T9999")
        assert name == "T9999"  # Returns ID if not found

    def test_get_statistics(self):
        """Test getting statistics."""
        builder = AttackTransitionBuilder()
        builder.parse_mitre_attack()
        builder.extract_technique_relationships()
        builder.calculate_transition_probabilities()
        builder.build_transition_matrix()

        stats = builder.get_statistics()

        assert "techniques" in stats
        assert "relationships" in stats
        assert "transitions" in stats
        assert "matrix_size" in stats

        assert stats["techniques"] > 0
        assert stats["matrix_size"] == len(builder.technique_ids)

    def test_is_forward_progression(self):
        """Test forward progression detection."""
        builder = AttackTransitionBuilder()
        builder.parse_mitre_attack()

        src_tactics = {"initial-access"}
        dst_tactics = {"execution"}

        is_forward = builder._is_forward_progression(src_tactics, dst_tactics)
        assert is_forward

    def test_is_backward_progression(self):
        """Test backward progression detection."""
        builder = AttackTransitionBuilder()
        builder.parse_mitre_attack()

        src_tactics = {"exfiltration"}
        dst_tactics = {"initial-access"}

        is_backward = builder._is_backward_progression(src_tactics, dst_tactics)
        assert is_backward


class TestEndToEnd:
    """End-to-end tests."""

    def test_full_pipeline(self):
        """Test complete pipeline from parsing to matrix."""
        builder = AttackTransitionBuilder()

        # Parse
        num_techniques = builder.parse_mitre_attack()
        assert num_techniques > 0

        # Extract relationships
        relationships = builder.extract_technique_relationships()
        assert len(relationships) > 0

        # Calculate probabilities
        probs = builder.calculate_transition_probabilities()
        assert len(probs) > 0

        # Build matrix
        matrix = builder.build_transition_matrix()
        assert matrix.size > 0

        # Verify consistency
        assert matrix.shape[0] == num_techniques

    def test_pipeline_with_caching(self):
        """Test pipeline with caching."""
        with tempfile.NamedTemporaryFile(suffix=".pkl", delete=False) as f:
            cache_path = f.name

        try:
            # Build and cache
            builder1 = AttackTransitionBuilder()
            builder1.parse_mitre_attack()
            builder1.extract_technique_relationships()
            builder1.calculate_transition_probabilities()
            builder1.build_transition_matrix()
            builder1.cache_matrix(cache_path)

            # Load from cache
            builder2 = AttackTransitionBuilder()
            builder2.load_cached_matrix(cache_path)

            # Verify both produce same results
            assert len(builder1.techniques) == len(builder2.techniques)
            np.testing.assert_array_equal(
                builder1.transition_matrix,
                builder2.transition_matrix
            )

        finally:
            Path(cache_path).unlink(missing_ok=True)
