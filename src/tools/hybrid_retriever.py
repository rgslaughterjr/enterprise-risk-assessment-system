"""
Hybrid Retriever for Advanced RAG System

Combines BM25 keyword search with semantic vector search for optimal retrieval.
Uses 0.9 semantic weight + 0.1 keyword weight (learned from Week 2).

Author: Enterprise Risk Assessment System
Date: 2025-11-15
Week: 7 Session 1 - Advanced RAG Foundation
"""

import logging
from typing import List, Tuple, Dict, Any, Optional
from langchain_core.documents import Document
from langchain_community.vectorstores import Chroma
from rank_bm25 import BM25Okapi
import re

logger = logging.getLogger(__name__)


class HybridRetriever:
    """
    Hybrid retriever combining BM25 keyword search and semantic vector search.

    Implements Week 2 learning: 90% semantic weight + 10% keyword weight
    for optimal retrieval performance.
    """

    def __init__(
        self,
        vectorstore: Optional[Chroma] = None,
        semantic_weight: float = 0.9,
        keyword_weight: float = 0.1,
        top_k: int = 20,
        final_k: int = 4
    ):
        """
        Initialize the hybrid retriever.

        Args:
            vectorstore: ChromaDB vectorstore for semantic search
            semantic_weight: Weight for semantic search (default 0.9 from Week 2)
            keyword_weight: Weight for keyword search (default 0.1 from Week 2)
            top_k: Number of candidates to retrieve from each method
            final_k: Number of final results to return after fusion

        Note:
            Weights should sum to 1.0 for proper score normalization.
        """
        self.vectorstore = vectorstore
        self.semantic_weight = semantic_weight
        self.keyword_weight = keyword_weight
        self.top_k = top_k
        self.final_k = final_k

        # BM25 components (initialized when corpus is added)
        self.bm25 = None
        self.corpus_docs: List[Document] = []
        self.tokenized_corpus: List[List[str]] = []

        logger.info(
            f"HybridRetriever initialized: semantic_weight={semantic_weight}, "
            f"keyword_weight={keyword_weight}, top_k={top_k}, final_k={final_k}"
        )

        # Validate weights
        if not abs(semantic_weight + keyword_weight - 1.0) < 0.01:
            logger.warning(
                f"Weights don't sum to 1.0: semantic={semantic_weight}, "
                f"keyword={keyword_weight}. Results may be improperly scaled."
            )

    def add_documents(self, documents: List[Document]) -> None:
        """
        Add documents to the retriever for BM25 indexing.

        Args:
            documents: List of Document objects to index

        Note:
            This builds the BM25 index. Must be called before retrieval.
        """
        try:
            if not documents:
                logger.warning("No documents provided to add_documents")
                return

            self.corpus_docs = documents
            self.tokenized_corpus = [self._tokenize(doc.page_content) for doc in documents]

            # Build BM25 index
            self.bm25 = BM25Okapi(self.tokenized_corpus)

            logger.info(f"Added {len(documents)} documents to BM25 index")

        except Exception as e:
            logger.error(f"Error adding documents to BM25 index: {e}", exc_info=True)
            raise

    def retrieve(
        self,
        query: str,
        k: Optional[int] = None,
        use_semantic: bool = True,
        use_keyword: bool = True
    ) -> List[Document]:
        """
        Retrieve documents using hybrid search.

        Args:
            query: Search query
            k: Number of results to return (default: self.final_k)
            use_semantic: Enable semantic search
            use_keyword: Enable keyword search

        Returns:
            List of top-k Document objects ranked by fused scores

        Example:
            >>> retriever = HybridRetriever(vectorstore=chroma)
            >>> retriever.add_documents(docs)
            >>> results = retriever.retrieve("security vulnerabilities", k=5)
            >>> len(results)
            5
        """
        try:
            if not query or not isinstance(query, str):
                logger.warning("Invalid query provided")
                return []

            k = k or self.final_k

            # Normalize query
            normalized_query = self._normalize_query(query)

            # Retrieve from both sources
            semantic_results = []
            keyword_results = []

            if use_semantic and self.vectorstore is not None:
                semantic_results = self.retrieve_semantic(normalized_query, k=self.top_k)

            if use_keyword and self.bm25 is not None:
                keyword_results = self.retrieve_keyword(normalized_query, k=self.top_k)

            # Handle edge cases
            if not semantic_results and not keyword_results:
                logger.warning("No results from either retrieval method")
                return []

            if not use_semantic or not semantic_results:
                logger.info("Using keyword-only retrieval")
                return [doc for doc, _ in keyword_results[:k]]

            if not use_keyword or not keyword_results:
                logger.info("Using semantic-only retrieval")
                return [doc for doc, _ in semantic_results[:k]]

            # Fuse results
            fused_docs = self.fuse_results(semantic_results, keyword_results, k=k)

            logger.info(
                f"Retrieved {len(fused_docs)} documents using hybrid search "
                f"(query: '{query[:50]}...')"
            )

            return fused_docs

        except Exception as e:
            logger.error(f"Error in hybrid retrieval: {e}", exc_info=True)
            return []

    def retrieve_semantic(
        self,
        query: str,
        k: int = 20
    ) -> List[Tuple[Document, float]]:
        """
        Retrieve documents using semantic vector search.

        Args:
            query: Search query
            k: Number of results to return

        Returns:
            List of (Document, score) tuples sorted by relevance

        Note:
            Requires vectorstore to be initialized.
        """
        try:
            if self.vectorstore is None:
                logger.warning("Vectorstore not initialized, skipping semantic search")
                return []

            if not query:
                logger.warning("Empty query for semantic search")
                return []

            # Use similarity search with scores
            results = self.vectorstore.similarity_search_with_score(query, k=k)

            # ChromaDB returns (doc, distance), convert distance to similarity
            # Lower distance = higher similarity, so we invert it
            scored_results = []
            for doc, distance in results:
                # Convert L2 distance to similarity score (0-1 range)
                # Using exponential decay: e^(-distance)
                import math
                similarity = math.exp(-distance)
                scored_results.append((doc, similarity))

            logger.info(f"Semantic search returned {len(scored_results)} results")
            return scored_results

        except Exception as e:
            logger.error(f"Error in semantic retrieval: {e}", exc_info=True)
            return []

    def retrieve_keyword(
        self,
        query: str,
        k: int = 20
    ) -> List[Tuple[Document, float]]:
        """
        Retrieve documents using BM25 keyword search.

        Args:
            query: Search query
            k: Number of results to return

        Returns:
            List of (Document, score) tuples sorted by BM25 score

        Note:
            Requires documents to be added via add_documents() first.
        """
        try:
            if self.bm25 is None:
                logger.warning("BM25 not initialized, call add_documents() first")
                return []

            if not query:
                logger.warning("Empty query for keyword search")
                return []

            if not self.corpus_docs:
                logger.warning("No documents in corpus")
                return []

            # Tokenize query
            tokenized_query = self._tokenize(query)

            # Get BM25 scores
            scores = self.bm25.get_scores(tokenized_query)

            # Create (doc, score) pairs and sort
            doc_scores = list(zip(self.corpus_docs, scores))
            doc_scores.sort(key=lambda x: x[1], reverse=True)

            # Return top k
            results = doc_scores[:k]

            logger.info(f"Keyword search returned {len(results)} results")
            return results

        except Exception as e:
            logger.error(f"Error in keyword retrieval: {e}", exc_info=True)
            return []

    def fuse_results(
        self,
        semantic_results: List[Tuple[Document, float]],
        keyword_results: List[Tuple[Document, float]],
        k: Optional[int] = None
    ) -> List[Document]:
        """
        Fuse semantic and keyword search results using weighted scores.

        Implements: final_score = 0.9 * semantic_score + 0.1 * keyword_score

        Args:
            semantic_results: List of (Document, score) from semantic search
            keyword_results: List of (Document, score) from keyword search
            k: Number of final results to return

        Returns:
            List of Documents ranked by fused scores

        Example:
            >>> semantic = [(doc1, 0.95), (doc2, 0.85)]
            >>> keyword = [(doc1, 0.70), (doc3, 0.80)]
            >>> fused = retriever.fuse_results(semantic, keyword, k=2)
        """
        try:
            k = k or self.final_k

            # Normalize scores to 0-1 range for each method
            semantic_normalized = self._normalize_scores(semantic_results)
            keyword_normalized = self._normalize_scores(keyword_results)

            # Build score maps (use doc page_content as key for deduplication)
            semantic_map = {doc.page_content: (doc, score) for doc, score in semantic_normalized}
            keyword_map = {doc.page_content: (doc, score) for doc, score in keyword_normalized}

            # Get all unique documents
            all_doc_keys = set(semantic_map.keys()) | set(keyword_map.keys())

            # Calculate fused scores
            fused_scores = []
            for doc_key in all_doc_keys:
                # Get scores (default to 0 if not present)
                doc, sem_score = semantic_map.get(doc_key, (None, 0.0))
                if doc is None:
                    doc, _ = keyword_map[doc_key]

                kw_score = keyword_map.get(doc_key, (doc, 0.0))[1]

                # Apply weighted fusion (Week 2 learning: 0.9 semantic, 0.1 keyword)
                fused_score = (
                    self.semantic_weight * sem_score +
                    self.keyword_weight * kw_score
                )

                fused_scores.append((doc, fused_score))

            # Sort by fused score and return top k
            fused_scores.sort(key=lambda x: x[1], reverse=True)
            final_docs = [doc for doc, _ in fused_scores[:k]]

            logger.info(
                f"Fused {len(semantic_results)} semantic + {len(keyword_results)} "
                f"keyword results into {len(final_docs)} final results"
            )

            return final_docs

        except Exception as e:
            logger.error(f"Error fusing results: {e}", exc_info=True)
            return []

    def _tokenize(self, text: str) -> List[str]:
        """
        Tokenize text for BM25.

        Args:
            text: Input text

        Returns:
            List of lowercase word tokens
        """
        # Simple word tokenization
        words = re.findall(r'\b\w+\b', text.lower())
        return words

    def _normalize_query(self, query: str) -> str:
        """
        Normalize query for consistent retrieval.

        Args:
            query: Raw query string

        Returns:
            Normalized query string
        """
        # Basic normalization: strip whitespace, lowercase
        normalized = query.strip().lower()
        return normalized

    def _normalize_scores(
        self,
        results: List[Tuple[Document, float]]
    ) -> List[Tuple[Document, float]]:
        """
        Normalize scores to 0-1 range using min-max normalization.

        Args:
            results: List of (Document, score) tuples

        Returns:
            List of (Document, normalized_score) tuples
        """
        if not results:
            return []

        scores = [score for _, score in results]

        # Handle edge case where all scores are the same
        min_score = min(scores)
        max_score = max(scores)

        if max_score == min_score:
            # All scores are the same, return uniform scores
            return [(doc, 1.0) for doc, _ in results]

        # Min-max normalization
        normalized = []
        for doc, score in results:
            norm_score = (score - min_score) / (max_score - min_score)
            normalized.append((doc, norm_score))

        return normalized

    def get_stats(self) -> Dict[str, Any]:
        """
        Get retriever statistics.

        Returns:
            Dictionary with retriever stats
        """
        return {
            "semantic_weight": self.semantic_weight,
            "keyword_weight": self.keyword_weight,
            "top_k": self.top_k,
            "final_k": self.final_k,
            "corpus_size": len(self.corpus_docs),
            "bm25_initialized": self.bm25 is not None,
            "vectorstore_initialized": self.vectorstore is not None
        }


def main():
    """Example usage of HybridRetriever."""
    # Configure logging
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )

    # Sample documents
    sample_docs = [
        Document(
            page_content="Machine learning algorithms detect security vulnerabilities in code.",
            metadata={"source": "doc1.pdf", "type": "security"}
        ),
        Document(
            page_content="Network firewalls protect against unauthorized access attempts.",
            metadata={"source": "doc2.pdf", "type": "security"}
        ),
        Document(
            page_content="Risk assessment frameworks evaluate potential threats systematically.",
            metadata={"source": "doc3.pdf", "type": "risk"}
        ),
        Document(
            page_content="Encryption algorithms secure data transmission across networks.",
            metadata={"source": "doc4.pdf", "type": "security"}
        ),
    ]

    # Initialize retriever (without vectorstore for this example)
    print("\n=== Hybrid Retriever Demo ===")
    retriever = HybridRetriever(
        vectorstore=None,  # Would use ChromaDB in practice
        semantic_weight=0.9,
        keyword_weight=0.1
    )

    # Add documents for BM25
    retriever.add_documents(sample_docs)

    # Test keyword-only search
    print("\n--- Keyword Search Only ---")
    results = retriever.retrieve(
        "security vulnerabilities networks",
        k=3,
        use_semantic=False,
        use_keyword=True
    )
    for i, doc in enumerate(results, 1):
        print(f"{i}. {doc.page_content[:60]}...")

    # Show stats
    print("\n--- Retriever Stats ---")
    stats = retriever.get_stats()
    for key, value in stats.items():
        print(f"{key}: {value}")


if __name__ == "__main__":
    main()
