"""
Control Deduplicator

Uses TF-IDF and fuzzy matching to deduplicate controls from multiple sources.
"""

from typing import Dict, List, Tuple
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.metrics.pairwise import cosine_similarity
import numpy as np
import logging

logger = logging.getLogger(__name__)


class ControlDeduplicator:
    """Deduplicate security controls using TF-IDF and similarity matching."""

    def __init__(self, similarity_threshold: float = 0.8):
        """
        Initialize deduplicator.

        Args:
            similarity_threshold: Threshold for considering controls duplicates (0.0-1.0)
        """
        self.similarity_threshold = similarity_threshold
        self.vectorizer = TfidfVectorizer(
            lowercase=True,
            stop_words='english',
            ngram_range=(1, 3),
            max_features=1000
        )
        logger.info(f"Initialized ControlDeduplicator (threshold={similarity_threshold})")

    def deduplicate_controls(self, controls: List[Dict],
                            merge_strategy: str = 'highest_confidence') -> List[Dict]:
        """
        Deduplicate list of controls.

        Args:
            controls: List of control dictionaries
            merge_strategy: How to merge duplicates ('highest_confidence', 'combine', 'first')

        Returns:
            Deduplicated list of controls
        """
        if not controls:
            return []

        logger.info(f"Deduplicating {len(controls)} controls...")

        # Build text representations for comparison
        control_texts = self._build_control_texts(controls)

        # Calculate similarity matrix
        similarity_matrix = self._calculate_similarity(control_texts)

        # Find duplicate groups
        duplicate_groups = self._find_duplicates(similarity_matrix)

        # Merge duplicates
        unique_controls = self._merge_duplicates(controls, duplicate_groups, merge_strategy)

        logger.info(f"Reduced to {len(unique_controls)} unique controls "
                   f"(removed {len(controls) - len(unique_controls)} duplicates)")

        return unique_controls

    def _build_control_texts(self, controls: List[Dict]) -> List[str]:
        """Build text representations for TF-IDF."""
        texts = []
        for control in controls:
            # Combine control_id, title, and description for comparison
            text_parts = [
                self._normalize_control_id(control.get('control_id', '')),
                control.get('title', ''),
                control.get('description', '')[:200]  # Limit description length
            ]
            texts.append(' '.join(text_parts))
        return texts

    def _normalize_control_id(self, control_id: str) -> str:
        """Normalize control ID for comparison (e.g., AC-1 vs AC-01)."""
        # Remove framework prefix variations
        normalized = control_id.upper().replace('NIST-', '').replace('CIS-', '').replace('ISO-', '')
        # Handle variations like AC-1 vs AC-01
        normalized = normalized.replace('-0', '-')
        return normalized

    def _calculate_similarity(self, texts: List[str]) -> np.ndarray:
        """Calculate TF-IDF similarity matrix."""
        if len(texts) < 2:
            return np.array([[1.0]])

        # Fit and transform texts
        tfidf_matrix = self.vectorizer.fit_transform(texts)

        # Calculate cosine similarity
        similarity_matrix = cosine_similarity(tfidf_matrix)

        return similarity_matrix

    def _find_duplicates(self, similarity_matrix: np.ndarray) -> List[List[int]]:
        """Find groups of duplicate controls."""
        n = similarity_matrix.shape[0]
        visited = set()
        duplicate_groups = []

        for i in range(n):
            if i in visited:
                continue

            # Find all controls similar to this one
            group = [i]
            for j in range(i + 1, n):
                if similarity_matrix[i, j] >= self.similarity_threshold:
                    group.append(j)
                    visited.add(j)

            if len(group) > 1:
                duplicate_groups.append(group)
                visited.add(i)

        return duplicate_groups

    def _merge_duplicates(self, controls: List[Dict],
                         duplicate_groups: List[List[int]],
                         merge_strategy: str) -> List[Dict]:
        """Merge duplicate controls based on strategy."""
        # Track which controls to keep
        merged_indices = set()
        for group in duplicate_groups:
            merged_indices.update(group)

        unique_controls = []

        # Add non-duplicates
        for i, control in enumerate(controls):
            if i not in merged_indices:
                unique_controls.append(control)

        # Merge duplicate groups
        for group in duplicate_groups:
            group_controls = [controls[i] for i in group]
            merged = self._merge_group(group_controls, merge_strategy)
            unique_controls.append(merged)

        return unique_controls

    def _merge_group(self, group_controls: List[Dict], strategy: str) -> Dict:
        """Merge a group of duplicate controls."""
        if strategy == 'highest_confidence':
            # Return control with highest confidence
            return max(group_controls, key=lambda c: c.get('confidence', 0.5))

        elif strategy == 'first':
            return group_controls[0]

        elif strategy == 'combine':
            # Combine information from all controls
            merged = group_controls[0].copy()

            # Collect all sources
            sources = []
            for ctrl in group_controls:
                source = ctrl.get('source', '')
                if source and source not in sources:
                    sources.append(source)

            merged['sources'] = sources
            merged['duplicate_count'] = len(group_controls)

            # Combine evidence
            evidence_parts = [ctrl.get('evidence', '') for ctrl in group_controls if ctrl.get('evidence')]
            if evidence_parts:
                merged['evidence'] = '; '.join(set(evidence_parts))

            # Take highest confidence
            merged['confidence'] = max(c.get('confidence', 0.5) for c in group_controls)

            return merged

        else:
            return group_controls[0]

    def find_similar_controls(self, control: Dict, control_library: List[Dict],
                             top_k: int = 5) -> List[Tuple[Dict, float]]:
        """
        Find similar controls in a library.

        Args:
            control: Control to find matches for
            control_library: Library of controls to search
            top_k: Number of top matches to return

        Returns:
            List of (control, similarity_score) tuples
        """
        if not control_library:
            return []

        # Build texts
        query_text = self._build_control_texts([control])[0]
        library_texts = self._build_control_texts(control_library)

        # Calculate similarities
        all_texts = [query_text] + library_texts
        tfidf_matrix = self.vectorizer.fit_transform(all_texts)
        similarities = cosine_similarity(tfidf_matrix[0:1], tfidf_matrix[1:])[0]

        # Get top k matches
        top_indices = np.argsort(similarities)[-top_k:][::-1]

        matches = [(control_library[i], float(similarities[i])) for i in top_indices]
        return matches
