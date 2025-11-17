"""
Document Classifier for ML-based document type classification.

This module provides machine learning-based document classification for:
- Security reports and assessments
- Compliance documents
- Technical specifications
- Incident reports
- Policy documents
- Audit reports
"""

import logging
from pathlib import Path
from typing import Dict, List, Tuple, Optional, Any
import pickle
import json

try:
    from sklearn.feature_extraction.text import TfidfVectorizer
    from sklearn.naive_bayes import MultinomialNB
    from sklearn.preprocessing import MultiLabelBinarizer
    import numpy as np
except ImportError as e:
    raise ImportError(f"Missing required dependencies for classification: {e}")

logger = logging.getLogger(__name__)


class DocumentClassifier:
    """
    Enterprise-grade ML-based document classifier.

    Features:
    - Multi-class classification
    - Multi-label classification support
    - TF-IDF feature extraction
    - Confidence scoring
    - Pre-trained models for security documents
    - Domain-specific classification
    """

    # Document type categories for security/risk assessment
    DOCUMENT_TYPES = {
        'security_report': [
            'vulnerability', 'penetration', 'pentest', 'security scan',
            'threat', 'exploit', 'cve', 'security assessment'
        ],
        'risk_assessment': [
            'risk register', 'risk assessment', 'risk analysis',
            'impact', 'likelihood', 'risk matrix', 'mitigation'
        ],
        'audit_report': [
            'audit', 'soc2', 'iso27001', 'compliance audit',
            'audit findings', 'audit recommendation'
        ],
        'policy_document': [
            'policy', 'procedure', 'standard', 'guideline',
            'acceptable use', 'security policy'
        ],
        'compliance_checklist': [
            'nist', 'pci-dss', 'hipaa', 'gdpr', 'compliance',
            'checklist', 'requirements', 'controls'
        ],
        'incident_report': [
            'incident', 'breach', 'post-mortem', 'incident response',
            'security incident', 'data breach'
        ],
        'technical_specification': [
            'architecture', 'technical design', 'specification',
            'configuration', 'implementation', 'technical documentation'
        ]
    }

    MIN_CONFIDENCE_THRESHOLD = 0.3

    def __init__(
        self,
        confidence_threshold: float = MIN_CONFIDENCE_THRESHOLD,
        max_features: int = 5000
    ):
        """
        Initialize document classifier.

        Args:
            confidence_threshold: Minimum confidence for classification (0-1)
            max_features: Maximum number of TF-IDF features
        """
        self.confidence_threshold = confidence_threshold
        self.max_features = max_features

        # Initialize TF-IDF vectorizer
        self.vectorizer = TfidfVectorizer(
            max_features=max_features,
            ngram_range=(1, 2),  # Unigrams and bigrams
            stop_words='english',
            lowercase=True,
            min_df=1,
            max_df=0.9
        )

        # Initialize classifier
        self.classifier = MultinomialNB(alpha=0.1)

        # Multi-label binarizer for multi-label classification
        self.mlb = None

        # Training state
        self.is_trained = False
        self._train_with_default_data()

    def _train_with_default_data(self):
        """Train classifier with default security document patterns."""
        try:
            documents = []
            labels = []

            # Generate synthetic training data from keywords
            for doc_type, keywords in self.DOCUMENT_TYPES.items():
                for keyword in keywords:
                    # Create synthetic documents with variations
                    doc = f"This document is about {keyword}. " * 3
                    documents.append(doc)
                    labels.append(doc_type)

            if documents:
                self.train_classifier(documents, labels)
                logger.info("Classifier trained with default security document patterns")

        except Exception as e:
            logger.warning(f"Could not train with default data: {e}")

    def classify_document(
        self,
        text: str,
        return_all_scores: bool = False
    ) -> Dict[str, float]:
        """
        Classify document text and return confidence scores.

        Args:
            text: Document text to classify
            return_all_scores: Return scores for all categories

        Returns:
            Dictionary mapping document types to confidence scores
        """
        try:
            if not self.is_trained:
                logger.warning("Classifier not trained, using keyword matching")
                return self._keyword_based_classification(text)

            # Extract features
            features = self.vectorizer.transform([text])

            # Get predictions with probabilities
            probabilities = self.classifier.predict_proba(features)[0]
            classes = self.classifier.classes_

            # Build results
            results = {}
            for class_label, prob in zip(classes, probabilities):
                if return_all_scores or prob >= self.confidence_threshold:
                    results[class_label] = float(prob)

            # Sort by confidence
            results = dict(sorted(results.items(), key=lambda x: x[1], reverse=True))

            return results

        except Exception as e:
            logger.error(f"Error classifying document: {e}")
            return self._keyword_based_classification(text)

    def _keyword_based_classification(self, text: str) -> Dict[str, float]:
        """
        Fallback keyword-based classification.

        Args:
            text: Document text

        Returns:
            Dictionary mapping document types to confidence scores
        """
        text_lower = text.lower()
        scores = {}

        for doc_type, keywords in self.DOCUMENT_TYPES.items():
            # Count keyword matches
            matches = sum(1 for keyword in keywords if keyword in text_lower)
            if matches > 0:
                # Normalize score
                score = min(1.0, matches / len(keywords))
                scores[doc_type] = score

        # Sort by score
        scores = dict(sorted(scores.items(), key=lambda x: x[1], reverse=True))

        return scores

    def predict_with_confidence(self, text: str) -> Tuple[str, float]:
        """
        Predict single best document type with confidence.

        Args:
            text: Document text to classify

        Returns:
            Tuple of (predicted_type, confidence_score)
        """
        try:
            results = self.classify_document(text, return_all_scores=True)

            if not results:
                return ('unknown', 0.0)

            # Get highest confidence prediction
            best_type = max(results.items(), key=lambda x: x[1])

            return best_type

        except Exception as e:
            logger.error(f"Error predicting document type: {e}")
            return ('unknown', 0.0)

    def classify_multi_label(
        self,
        text: str,
        threshold: Optional[float] = None
    ) -> Dict[str, float]:
        """
        Classify document with multiple labels.

        Args:
            text: Document text to classify
            threshold: Confidence threshold (uses default if None)

        Returns:
            Dictionary of labels with confidence scores
        """
        threshold = threshold or self.confidence_threshold

        try:
            results = self.classify_document(text, return_all_scores=True)

            # Filter by threshold
            multi_labels = {
                label: score
                for label, score in results.items()
                if score >= threshold
            }

            return multi_labels

        except Exception as e:
            logger.error(f"Error in multi-label classification: {e}")
            return {}

    def train_classifier(
        self,
        documents: List[str],
        labels: List[str]
    ) -> bool:
        """
        Train classifier with custom document dataset.

        Args:
            documents: List of document texts
            labels: List of corresponding labels

        Returns:
            True if training successful
        """
        try:
            if len(documents) != len(labels):
                logger.error("Documents and labels must have same length")
                return False

            if len(documents) == 0:
                logger.error("No training documents provided")
                return False

            # Extract features
            X = self.vectorizer.fit_transform(documents)

            # Train classifier
            self.classifier.fit(X, labels)

            self.is_trained = True

            logger.info(
                f"Classifier trained with {len(documents)} documents, "
                f"{len(set(labels))} classes"
            )

            return True

        except Exception as e:
            logger.error(f"Error training classifier: {e}")
            return False

    def get_document_features(self, text: str) -> np.ndarray:
        """
        Extract TF-IDF features from document text.

        Args:
            text: Document text

        Returns:
            Feature vector as numpy array
        """
        try:
            if not self.is_trained:
                logger.warning("Classifier not trained, fitting vectorizer")
                self.vectorizer.fit([text])

            features = self.vectorizer.transform([text])
            return features.toarray()[0]

        except Exception as e:
            logger.error(f"Error extracting features: {e}")
            return np.array([])

    def get_top_features(
        self,
        doc_type: str,
        n: int = 10
    ) -> List[Tuple[str, float]]:
        """
        Get top TF-IDF features for a document type.

        Args:
            doc_type: Document type label
            n: Number of top features to return

        Returns:
            List of (feature, score) tuples
        """
        try:
            if not self.is_trained:
                logger.warning("Classifier not trained")
                return []

            # Get class index
            classes = self.classifier.classes_
            if doc_type not in classes:
                logger.warning(f"Document type '{doc_type}' not in trained classes")
                return []

            class_idx = np.where(classes == doc_type)[0][0]

            # Get feature log probabilities
            feature_log_prob = self.classifier.feature_log_prob_[class_idx]

            # Get feature names
            feature_names = self.vectorizer.get_feature_names_out()

            # Get top N features
            top_indices = np.argsort(feature_log_prob)[-n:][::-1]

            top_features = [
                (feature_names[i], float(feature_log_prob[i]))
                for i in top_indices
            ]

            return top_features

        except Exception as e:
            logger.error(f"Error getting top features: {e}")
            return []

    def save_model(self, filepath: str) -> bool:
        """
        Save trained model to file.

        Args:
            filepath: Path to save model

        Returns:
            True if successful
        """
        try:
            model_data = {
                'vectorizer': self.vectorizer,
                'classifier': self.classifier,
                'is_trained': self.is_trained,
                'confidence_threshold': self.confidence_threshold,
                'max_features': self.max_features
            }

            with open(filepath, 'wb') as f:
                pickle.dump(model_data, f)

            logger.info(f"Model saved to {filepath}")
            return True

        except Exception as e:
            logger.error(f"Error saving model: {e}")
            return False

    def load_model(self, filepath: str) -> bool:
        """
        Load trained model from file.

        Args:
            filepath: Path to model file

        Returns:
            True if successful
        """
        try:
            filepath = Path(filepath)

            if not filepath.exists():
                logger.error(f"Model file not found: {filepath}")
                return False

            with open(filepath, 'rb') as f:
                model_data = pickle.load(f)

            self.vectorizer = model_data['vectorizer']
            self.classifier = model_data['classifier']
            self.is_trained = model_data['is_trained']
            self.confidence_threshold = model_data.get(
                'confidence_threshold',
                self.MIN_CONFIDENCE_THRESHOLD
            )
            self.max_features = model_data.get('max_features', 5000)

            logger.info(f"Model loaded from {filepath}")
            return True

        except Exception as e:
            logger.error(f"Error loading model: {e}")
            return False

    def get_classification_report(
        self,
        text: str
    ) -> Dict[str, Any]:
        """
        Get comprehensive classification report for document.

        Args:
            text: Document text

        Returns:
            Dictionary with classification details
        """
        try:
            # Get classification
            all_scores = self.classify_document(text, return_all_scores=True)
            best_type, best_confidence = self.predict_with_confidence(text)
            multi_labels = self.classify_multi_label(text)

            # Get top features
            features = self.get_document_features(text)

            report = {
                'primary_classification': best_type,
                'primary_confidence': best_confidence,
                'all_classifications': all_scores,
                'multi_label_classifications': multi_labels,
                'feature_count': len(features),
                'is_high_confidence': best_confidence >= 0.7,
                'is_low_confidence': best_confidence < self.confidence_threshold,
                'suggested_labels': list(multi_labels.keys())
            }

            return report

        except Exception as e:
            logger.error(f"Error generating classification report: {e}")
            return {
                'primary_classification': 'unknown',
                'primary_confidence': 0.0,
                'error': str(e)
            }

    def get_supported_types(self) -> List[str]:
        """
        Get list of supported document types.

        Returns:
            List of document type labels
        """
        if self.is_trained:
            return list(self.classifier.classes_)
        else:
            return list(self.DOCUMENT_TYPES.keys())

    def get_statistics(self) -> Dict[str, Any]:
        """
        Get classifier statistics.

        Returns:
            Dictionary with classifier information
        """
        return {
            'is_trained': self.is_trained,
            'supported_types': len(self.get_supported_types()),
            'document_types': self.get_supported_types(),
            'confidence_threshold': self.confidence_threshold,
            'max_features': self.max_features,
            'feature_count': len(self.vectorizer.get_feature_names_out()) if self.is_trained else 0
        }
