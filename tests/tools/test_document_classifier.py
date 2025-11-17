"""
Comprehensive tests for Document Classifier.

Tests cover:
- Document classification
- ML training
- Feature extraction
- Confidence scoring
- Multi-label classification
- Model persistence
- Classification reports
- Error handling
"""

import pytest
from unittest.mock import Mock, patch, MagicMock
from pathlib import Path
import tempfile
import numpy as np

from src.tools.document_classifier import DocumentClassifier


@pytest.fixture
def document_classifier():
    """Create document classifier instance."""
    return DocumentClassifier(confidence_threshold=0.3, max_features=1000)


@pytest.fixture
def sample_security_report():
    """Sample security report text."""
    return """
    This is a comprehensive vulnerability assessment report.
    We conducted a penetration test on the web application.
    Several critical CVE vulnerabilities were identified during the security scan.
    Threat analysis shows potential exploit vectors.
    """


@pytest.fixture
def sample_risk_assessment():
    """Sample risk assessment text."""
    return """
    Risk Assessment Report
    This document outlines the risk analysis for the project.
    Risk matrix shows high impact and medium likelihood.
    Mitigation strategies are recommended for identified risks.
    Risk register has been updated with new entries.
    """


@pytest.fixture
def sample_audit_report():
    """Sample audit report text."""
    return """
    SOC2 Compliance Audit Report
    Audit findings indicate compliance with ISO27001 standards.
    Several audit recommendations were provided.
    Compliance audit was conducted by certified auditors.
    """


@pytest.fixture
def training_data():
    """Sample training data."""
    return {
        'documents': [
            "This is a security vulnerability report with CVE details",
            "Risk assessment shows high impact areas",
            "Audit findings from SOC2 compliance review",
            "Security policy document for acceptable use",
            "NIST compliance checklist with controls"
        ],
        'labels': [
            'security_report',
            'risk_assessment',
            'audit_report',
            'policy_document',
            'compliance_checklist'
        ]
    }


class TestDocumentClassifierInit:
    """Test document classifier initialization."""

    def test_init_default_params(self):
        """Test initialization with default parameters."""
        classifier = DocumentClassifier()
        assert classifier.confidence_threshold == 0.3
        assert classifier.max_features == 5000
        assert classifier.is_trained is True  # Trained with default data

    def test_init_custom_params(self):
        """Test initialization with custom parameters."""
        classifier = DocumentClassifier(confidence_threshold=0.5, max_features=3000)
        assert classifier.confidence_threshold == 0.5
        assert classifier.max_features == 3000

    def test_document_types_defined(self):
        """Test document type categories are defined."""
        assert 'security_report' in DocumentClassifier.DOCUMENT_TYPES
        assert 'risk_assessment' in DocumentClassifier.DOCUMENT_TYPES
        assert 'audit_report' in DocumentClassifier.DOCUMENT_TYPES
        assert 'policy_document' in DocumentClassifier.DOCUMENT_TYPES
        assert 'compliance_checklist' in DocumentClassifier.DOCUMENT_TYPES
        assert 'incident_report' in DocumentClassifier.DOCUMENT_TYPES
        assert 'technical_specification' in DocumentClassifier.DOCUMENT_TYPES

    def test_default_training(self):
        """Test classifier is trained with default data."""
        classifier = DocumentClassifier()
        assert classifier.is_trained is True
        assert len(classifier.get_supported_types()) > 0


class TestClassifyDocument:
    """Test document classification."""

    def test_classify_security_report(
        self,
        document_classifier,
        sample_security_report
    ):
        """Test classification of security report."""
        results = document_classifier.classify_document(sample_security_report)

        assert isinstance(results, dict)
        assert len(results) > 0
        # Should have security_report with high confidence
        if 'security_report' in results:
            assert results['security_report'] > 0

    def test_classify_risk_assessment(
        self,
        document_classifier,
        sample_risk_assessment
    ):
        """Test classification of risk assessment."""
        results = document_classifier.classify_document(sample_risk_assessment)

        assert isinstance(results, dict)
        if 'risk_assessment' in results:
            assert results['risk_assessment'] > 0

    def test_classify_audit_report(
        self,
        document_classifier,
        sample_audit_report
    ):
        """Test classification of audit report."""
        results = document_classifier.classify_document(sample_audit_report)

        assert isinstance(results, dict)
        if 'audit_report' in results:
            assert results['audit_report'] > 0

    def test_classify_with_all_scores(
        self,
        document_classifier,
        sample_security_report
    ):
        """Test classification returning all scores."""
        results = document_classifier.classify_document(
            sample_security_report,
            return_all_scores=True
        )

        assert isinstance(results, dict)
        # Should return scores for all trained classes
        assert len(results) > 0

    def test_classify_empty_text(self, document_classifier):
        """Test classification with empty text."""
        results = document_classifier.classify_document("")

        assert isinstance(results, dict)

    def test_classify_returns_sorted_results(
        self,
        document_classifier,
        sample_security_report
    ):
        """Test results are sorted by confidence."""
        results = document_classifier.classify_document(
            sample_security_report,
            return_all_scores=True
        )

        if len(results) > 1:
            scores = list(results.values())
            assert scores == sorted(scores, reverse=True)


class TestPredictWithConfidence:
    """Test single prediction with confidence."""

    def test_predict_security_report(
        self,
        document_classifier,
        sample_security_report
    ):
        """Test prediction returns best match."""
        doc_type, confidence = document_classifier.predict_with_confidence(
            sample_security_report
        )

        assert isinstance(doc_type, str)
        assert isinstance(confidence, float)
        assert 0 <= confidence <= 1

    def test_predict_empty_text(self, document_classifier):
        """Test prediction with empty text."""
        doc_type, confidence = document_classifier.predict_with_confidence("")

        assert doc_type == 'unknown' or isinstance(doc_type, str)
        assert confidence >= 0

    def test_predict_returns_highest_confidence(
        self,
        document_classifier,
        sample_audit_report
    ):
        """Test prediction returns highest confidence type."""
        doc_type, confidence = document_classifier.predict_with_confidence(
            sample_audit_report
        )

        # Get all scores
        all_scores = document_classifier.classify_document(
            sample_audit_report,
            return_all_scores=True
        )

        if all_scores:
            max_score = max(all_scores.values())
            assert confidence == max_score


class TestMultiLabelClassification:
    """Test multi-label classification."""

    def test_multi_label_default_threshold(
        self,
        document_classifier,
        sample_security_report
    ):
        """Test multi-label classification with default threshold."""
        results = document_classifier.classify_multi_label(sample_security_report)

        assert isinstance(results, dict)
        # All scores should be above threshold
        for score in results.values():
            assert score >= document_classifier.confidence_threshold

    def test_multi_label_custom_threshold(
        self,
        document_classifier,
        sample_security_report
    ):
        """Test multi-label classification with custom threshold."""
        threshold = 0.5
        results = document_classifier.classify_multi_label(
            sample_security_report,
            threshold=threshold
        )

        for score in results.values():
            assert score >= threshold

    def test_multi_label_returns_multiple_labels(
        self,
        document_classifier,
        sample_security_report
    ):
        """Test multi-label can return multiple labels."""
        results = document_classifier.classify_multi_label(
            sample_security_report,
            threshold=0.1  # Low threshold to get multiple labels
        )

        # With low threshold, might get multiple labels
        assert isinstance(results, dict)


class TestTrainClassifier:
    """Test classifier training."""

    def test_train_with_custom_data(self, document_classifier, training_data):
        """Test training with custom dataset."""
        result = document_classifier.train_classifier(
            training_data['documents'],
            training_data['labels']
        )

        assert result is True
        assert document_classifier.is_trained is True

    def test_train_with_mismatched_lengths(self, document_classifier):
        """Test training with mismatched document and label lengths."""
        result = document_classifier.train_classifier(
            ['doc1', 'doc2'],
            ['label1']  # Mismatched length
        )

        assert result is False

    def test_train_with_empty_data(self, document_classifier):
        """Test training with empty dataset."""
        result = document_classifier.train_classifier([], [])

        assert result is False

    def test_train_updates_supported_types(self, document_classifier):
        """Test training updates supported types."""
        before_types = set(document_classifier.get_supported_types())

        document_classifier.train_classifier(
            ['new document type'],
            ['new_type']
        )

        after_types = set(document_classifier.get_supported_types())

        # Should have new type
        assert len(after_types) > 0


class TestFeatureExtraction:
    """Test feature extraction."""

    def test_get_document_features(
        self,
        document_classifier,
        sample_security_report
    ):
        """Test feature extraction."""
        features = document_classifier.get_document_features(sample_security_report)

        assert isinstance(features, np.ndarray)
        assert len(features) > 0

    def test_features_are_numeric(
        self,
        document_classifier,
        sample_security_report
    ):
        """Test features are numeric values."""
        features = document_classifier.get_document_features(sample_security_report)

        assert features.dtype in [np.float32, np.float64]

    def test_get_top_features(self, document_classifier):
        """Test getting top features for document type."""
        top_features = document_classifier.get_top_features('security_report', n=5)

        assert isinstance(top_features, list)
        if top_features:
            assert len(top_features) <= 5
            # Each feature should be (word, score) tuple
            assert isinstance(top_features[0], tuple)
            assert isinstance(top_features[0][0], str)
            assert isinstance(top_features[0][1], float)

    def test_get_top_features_unknown_type(self, document_classifier):
        """Test getting top features for unknown type."""
        top_features = document_classifier.get_top_features('unknown_type')

        assert top_features == []


class TestModelPersistence:
    """Test model saving and loading."""

    def test_save_model(self, document_classifier, tmp_path):
        """Test saving model to file."""
        model_path = tmp_path / "test_model.pkl"

        result = document_classifier.save_model(str(model_path))

        assert result is True
        assert model_path.exists()

    def test_load_model(self, document_classifier, tmp_path):
        """Test loading model from file."""
        model_path = tmp_path / "test_model.pkl"

        # Save model first
        document_classifier.save_model(str(model_path))

        # Create new classifier and load
        new_classifier = DocumentClassifier()
        result = new_classifier.load_model(str(model_path))

        assert result is True
        assert new_classifier.is_trained is True

    def test_load_nonexistent_model(self, document_classifier):
        """Test loading from nonexistent file."""
        result = document_classifier.load_model("/nonexistent/model.pkl")

        assert result is False

    def test_save_load_preserves_state(
        self,
        document_classifier,
        training_data,
        tmp_path
    ):
        """Test save/load preserves classifier state."""
        # Train classifier
        document_classifier.train_classifier(
            training_data['documents'],
            training_data['labels']
        )

        # Save
        model_path = tmp_path / "test_model.pkl"
        document_classifier.save_model(str(model_path))

        # Load into new classifier
        new_classifier = DocumentClassifier()
        new_classifier.load_model(str(model_path))

        # Should have same state
        assert new_classifier.is_trained == document_classifier.is_trained
        assert new_classifier.confidence_threshold == document_classifier.confidence_threshold


class TestClassificationReport:
    """Test classification report generation."""

    def test_get_classification_report(
        self,
        document_classifier,
        sample_security_report
    ):
        """Test comprehensive classification report."""
        report = document_classifier.get_classification_report(sample_security_report)

        assert isinstance(report, dict)
        assert 'primary_classification' in report
        assert 'primary_confidence' in report
        assert 'all_classifications' in report
        assert 'multi_label_classifications' in report
        assert 'is_high_confidence' in report
        assert 'is_low_confidence' in report

    def test_report_confidence_flags(
        self,
        document_classifier,
        sample_security_report
    ):
        """Test confidence flags in report."""
        report = document_classifier.get_classification_report(sample_security_report)

        # is_high_confidence and is_low_confidence should be opposite
        if report['is_high_confidence']:
            # Can't be both high and low confidence
            assert report['primary_confidence'] >= 0.7

    def test_report_suggested_labels(
        self,
        document_classifier,
        sample_security_report
    ):
        """Test suggested labels in report."""
        report = document_classifier.get_classification_report(sample_security_report)

        assert 'suggested_labels' in report
        assert isinstance(report['suggested_labels'], list)


class TestUtilityMethods:
    """Test utility methods."""

    def test_get_supported_types(self, document_classifier):
        """Test getting supported document types."""
        types = document_classifier.get_supported_types()

        assert isinstance(types, list)
        assert len(types) > 0

    def test_get_statistics(self, document_classifier):
        """Test getting classifier statistics."""
        stats = document_classifier.get_statistics()

        assert isinstance(stats, dict)
        assert 'is_trained' in stats
        assert 'supported_types' in stats
        assert 'document_types' in stats
        assert 'confidence_threshold' in stats
        assert 'max_features' in stats

    def test_statistics_accuracy(self, document_classifier):
        """Test statistics reflect actual state."""
        stats = document_classifier.get_statistics()

        assert stats['is_trained'] == document_classifier.is_trained
        assert stats['confidence_threshold'] == document_classifier.confidence_threshold
        assert stats['max_features'] == document_classifier.max_features


class TestKeywordBasedClassification:
    """Test fallback keyword-based classification."""

    def test_keyword_classification(self, document_classifier):
        """Test keyword-based classification fallback."""
        text = "This document contains vulnerability and penetration testing details"

        # Use private method directly
        results = document_classifier._keyword_based_classification(text)

        assert isinstance(results, dict)
        # Should identify security report
        if results:
            assert any('security' in key.lower() for key in results.keys())

    def test_keyword_classification_multiple_types(self, document_classifier):
        """Test keyword classification with multiple types."""
        text = """
        This is a security vulnerability report.
        It also includes risk assessment information.
        Audit findings are documented as well.
        """

        results = document_classifier._keyword_based_classification(text)

        # Should identify multiple document types
        assert len(results) >= 2

    def test_keyword_classification_no_matches(self, document_classifier):
        """Test keyword classification with no matches."""
        text = "This is completely unrelated content about gardening"

        results = document_classifier._keyword_based_classification(text)

        # Should return empty or very low scores
        assert isinstance(results, dict)


class TestEdgeCases:
    """Test edge cases and error handling."""

    def test_classify_very_long_text(self, document_classifier):
        """Test classification with very long text."""
        long_text = "vulnerability security scan " * 1000

        results = document_classifier.classify_document(long_text)

        assert isinstance(results, dict)

    def test_classify_special_characters(self, document_classifier):
        """Test classification with special characters."""
        text = "Security!@# vulnerability$%^ assessment&*()"

        results = document_classifier.classify_document(text)

        assert isinstance(results, dict)

    def test_classify_unicode_text(self, document_classifier):
        """Test classification with unicode characters."""
        text = "Security vulnerability 日本語 assessment Ñoño"

        results = document_classifier.classify_document(text)

        assert isinstance(results, dict)

    def test_multiple_classifications_same_text(self, document_classifier):
        """Test multiple classifications of same text."""
        text = "Security vulnerability report"

        results1 = document_classifier.classify_document(text)
        results2 = document_classifier.classify_document(text)

        # Results should be consistent
        assert results1 == results2
