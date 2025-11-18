"""Control deduplication using TF-IDF similarity matching.

This module identifies and merges duplicate security controls discovered from
multiple sources using TF-IDF vectorization and cosine similarity.
"""

import logging
from typing import List, Dict, Any, Optional, Tuple
from collections import defaultdict
from datetime import datetime

import numpy as np
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.metrics.pairwise import cosine_similarity

logger = logging.getLogger(__name__)


class ControlDeduplicator:
    """Deduplicates security controls using TF-IDF and cosine similarity.

    Uses text vectorization to identify controls that are likely duplicates
    based on their descriptions and titles, even when discovered from different sources.
    """

    def __init__(self, similarity_threshold: float = 0.85):
        """Initialize control deduplicator.

        Args:
            similarity_threshold: Cosine similarity threshold for considering controls
                                as duplicates (0.0 to 1.0). Default: 0.85
        """
        self.similarity_threshold = similarity_threshold
        self.vectorizer = TfidfVectorizer(
            max_features=500,
            stop_words="english",
            ngram_range=(1, 2),
            min_df=1,
        )

        logger.info(f"Control deduplicator initialized with threshold={similarity_threshold}")

    def deduplicate_controls(
        self,
        controls: List[Dict[str, Any]],
        threshold: Optional[float] = None,
    ) -> List[Dict[str, Any]]:
        """Identify and merge duplicate controls.

        Args:
            controls: List of control dictionaries to deduplicate
            threshold: Override default similarity threshold

        Returns:
            List of unique controls with merged metadata

        Example:
            >>> deduplicator = ControlDeduplicator()
            >>> unique = deduplicator.deduplicate_controls(all_controls)
        """
        if not controls:
            logger.warning("Empty controls list provided")
            return []

        if threshold is None:
            threshold = self.similarity_threshold

        logger.info(f"Deduplicating {len(controls)} controls with threshold={threshold}")

        # First pass: Exact ID matching
        id_groups = self._group_by_id(controls)

        # Second pass: Similarity matching within each ID group and orphans
        unique_controls = []
        total_duplicates = 0

        for control_id, control_list in id_groups.items():
            if len(control_list) == 1:
                # Single control with this ID, no deduplication needed
                unique_controls.append(control_list[0])
            else:
                # Multiple controls with same ID, merge them
                logger.info(f"Found {len(control_list)} instances of control {control_id}")

                if control_id == "UNKNOWN":
                    # For controls without IDs, use similarity matching
                    similar_groups = self._group_by_similarity(control_list, threshold)

                    for group in similar_groups:
                        merged = self.merge_duplicate_controls(group)
                        unique_controls.append(merged)
                        if len(group) > 1:
                            total_duplicates += len(group) - 1
                else:
                    # For controls with same ID, merge directly
                    merged = self.merge_duplicate_controls(control_list)
                    unique_controls.append(merged)
                    total_duplicates += len(control_list) - 1

        logger.info(
            f"Deduplication complete: {len(controls)} → {len(unique_controls)} "
            f"({total_duplicates} duplicates merged)"
        )

        return unique_controls

    def _group_by_id(self, controls: List[Dict[str, Any]]) -> Dict[str, List[Dict[str, Any]]]:
        """Group controls by their ID.

        Args:
            controls: List of control dictionaries

        Returns:
            Dictionary mapping control IDs to lists of controls
        """
        groups = defaultdict(list)

        for control in controls:
            control_id = control.get("id", "UNKNOWN")
            groups[control_id].append(control)

        logger.info(f"Grouped controls into {len(groups)} ID groups")
        return dict(groups)

    def _group_by_similarity(
        self,
        controls: List[Dict[str, Any]],
        threshold: float,
    ) -> List[List[Dict[str, Any]]]:
        """Group controls by text similarity.

        Args:
            controls: List of control dictionaries
            threshold: Similarity threshold

        Returns:
            List of control groups (each group is a list of similar controls)
        """
        if len(controls) <= 1:
            return [controls]

        # Prepare text for vectorization
        texts = []
        for control in controls:
            text = self._prepare_control_text(control)
            texts.append(text)

        # Vectorize and compute similarity
        try:
            tfidf_matrix = self.vectorizer.fit_transform(texts)
            similarity_matrix = cosine_similarity(tfidf_matrix)
        except Exception as e:
            logger.error(f"Error computing similarity: {str(e)}")
            # Return each control as its own group
            return [[c] for c in controls]

        # Group similar controls
        groups = []
        assigned = set()

        for i in range(len(controls)):
            if i in assigned:
                continue

            # Start new group
            group = [controls[i]]
            assigned.add(i)

            # Find similar controls
            for j in range(i + 1, len(controls)):
                if j in assigned:
                    continue

                if similarity_matrix[i, j] >= threshold:
                    group.append(controls[j])
                    assigned.add(j)

            groups.append(group)

        logger.info(f"Grouped {len(controls)} controls into {len(groups)} similarity groups")
        return groups

    def _prepare_control_text(self, control: Dict[str, Any]) -> str:
        """Prepare control text for vectorization.

        Args:
            control: Control dictionary

        Returns:
            Combined text from title, description, and context
        """
        parts = []

        # Title (weighted 2x)
        title = control.get("title", "")
        if title:
            parts.append(title)
            parts.append(title)  # Add twice for higher weight

        # Description
        description = control.get("description", "")
        if description:
            parts.append(description)

        # Context/notes
        context = control.get("context", "") or control.get("notes", "")
        if context:
            parts.append(context)

        # Framework and category for better matching
        framework = control.get("framework", "")
        if framework:
            parts.append(framework)

        category = control.get("category", "")
        if category:
            parts.append(category)

        return " ".join(parts)

    def find_similar_controls(
        self,
        control: Dict[str, Any],
        candidates: List[Dict[str, Any]],
        threshold: Optional[float] = None,
    ) -> List[Tuple[Dict[str, Any], float]]:
        """Find controls similar to a given control.

        Args:
            control: Reference control
            candidates: List of candidate controls to compare
            threshold: Similarity threshold (uses instance default if None)

        Returns:
            List of (control, similarity_score) tuples, sorted by score descending

        Example:
            >>> deduplicator = ControlDeduplicator()
            >>> similar = deduplicator.find_similar_controls(my_control, all_controls)
        """
        if threshold is None:
            threshold = self.similarity_threshold

        if not candidates:
            return []

        # Prepare texts
        reference_text = self._prepare_control_text(control)
        candidate_texts = [self._prepare_control_text(c) for c in candidates]

        all_texts = [reference_text] + candidate_texts

        try:
            # Vectorize
            tfidf_matrix = self.vectorizer.fit_transform(all_texts)

            # Compute similarity against reference (first item)
            similarities = cosine_similarity(tfidf_matrix[0:1], tfidf_matrix[1:])[0]

            # Build results
            results = []
            for i, score in enumerate(similarities):
                if score >= threshold:
                    results.append((candidates[i], float(score)))

            # Sort by similarity descending
            results.sort(key=lambda x: x[1], reverse=True)

            logger.info(f"Found {len(results)} similar controls (threshold={threshold})")
            return results

        except Exception as e:
            logger.error(f"Error finding similar controls: {str(e)}")
            return []

    def merge_duplicate_controls(
        self,
        control_group: List[Dict[str, Any]],
    ) -> Dict[str, Any]:
        """Merge a group of duplicate controls into a single control.

        Args:
            control_group: List of duplicate control dictionaries

        Returns:
            Merged control dictionary with combined metadata

        Example:
            >>> deduplicator = ControlDeduplicator()
            >>> merged = deduplicator.merge_duplicate_controls(duplicate_group)
        """
        if not control_group:
            logger.warning("Empty control group provided")
            return {}

        if len(control_group) == 1:
            return control_group[0]

        logger.info(f"Merging {len(control_group)} duplicate controls")

        # Start with first control as base
        merged = control_group[0].copy()

        # Collect all sources
        all_sources = set()
        all_source_details = []

        for control in control_group:
            source = control.get("source", "unknown")
            all_sources.add(source)

            # Collect detailed source information
            source_info = {
                "source": source,
                "discovered_at": control.get("discovered_at"),
            }

            # Add source-specific metadata
            if "source_page" in control:
                source_info["source_page"] = control["source_page"]
            if "source_file" in control:
                source_info["source_file"] = control["source_file"]
            if "file_name" in control:
                source_info["file_name"] = control["file_name"]

            all_source_details.append(source_info)

        # Merge metadata
        merged["sources"] = list(all_sources)
        merged["source_count"] = len(all_sources)
        merged["source_details"] = all_source_details
        merged["duplicate_count"] = len(control_group)
        merged["merged_at"] = datetime.utcnow().isoformat()

        # Use longest/most detailed description
        descriptions = [c.get("description", "") for c in control_group if c.get("description")]
        if descriptions:
            merged["description"] = max(descriptions, key=len)

        # Use longest title
        titles = [c.get("title", "") for c in control_group if c.get("title")]
        if titles:
            merged["title"] = max(titles, key=len)

        # Merge effectiveness scores (average)
        scores = [
            c.get("effectiveness_score")
            for c in control_group
            if c.get("effectiveness_score") is not None
        ]
        if scores:
            # Convert to floats
            numeric_scores = []
            for score in scores:
                try:
                    numeric_scores.append(float(score))
                except (ValueError, TypeError):
                    continue

            if numeric_scores:
                merged["effectiveness_score"] = sum(numeric_scores) / len(numeric_scores)

        # Merge implementation status (take most implemented)
        status_priority = {
            "Implemented": 3,
            "Partially Implemented": 2,
            "Not Implemented": 1,
            "Planned": 0,
        }

        statuses = [c.get("implementation_status") for c in control_group if c.get("implementation_status")]
        if statuses:
            best_status = max(statuses, key=lambda s: status_priority.get(s, 0))
            merged["implementation_status"] = best_status

        logger.info(f"Merged control {merged.get('id')} from {len(all_sources)} sources")
        return merged

    def get_deduplication_stats(
        self,
        original_count: int,
        deduplicated_controls: List[Dict[str, Any]],
    ) -> Dict[str, Any]:
        """Calculate deduplication statistics.

        Args:
            original_count: Number of controls before deduplication
            deduplicated_controls: List of deduplicated controls

        Returns:
            Statistics dictionary
        """
        final_count = len(deduplicated_controls)
        duplicates_removed = original_count - final_count
        dedup_rate = (duplicates_removed / original_count * 100) if original_count > 0 else 0

        # Count controls by source count
        multi_source = sum(1 for c in deduplicated_controls if c.get("source_count", 1) > 1)

        # Get source distribution
        source_dist = defaultdict(int)
        for control in deduplicated_controls:
            for source in control.get("sources", [control.get("source", "unknown")]):
                source_dist[source] += 1

        stats = {
            "original_count": original_count,
            "unique_count": final_count,
            "duplicates_removed": duplicates_removed,
            "deduplication_rate": round(dedup_rate, 2),
            "multi_source_controls": multi_source,
            "source_distribution": dict(source_dist),
        }

        logger.info(f"Deduplication stats: {duplicates_removed} duplicates removed ({dedup_rate:.1f}%)")
        return stats
