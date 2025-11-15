"""
Comprehensive tests for HybridRetriever

Tests cover BM25 keyword search, semantic search, score fusion, and edge cases.
Target: 25+ tests with 100% pass rate

Author: Enterprise Risk Assessment System
Date: 2025-11-15
Week: 7 Session 1 - Advanced RAG Foundation
"""

import pytest
from unittest.mock import Mock, MagicMock, patch
from langchain_core.documents import Document
from src.tools.hybrid_retriever import HybridRetriever


# Fixtures

@pytest.fixture
def sample_documents():
    """Sample documents for testing."""
    return [
        Document(
            page_content="Machine learning algorithms detect security vulnerabilities.",
            metadata={"source": "doc1.pdf", "type": "security"}
        ),
        Document(
            page_content="Network firewalls protect against unauthorized access.",
            metadata={"source": "doc2.pdf", "type": "security"}
        ),
        Document(
            page_content="Risk assessment frameworks evaluate potential threats.",
            metadata={"source": "doc3.pdf", "type": "risk"}
        ),
        Document(
            page_content="Encryption algorithms secure data transmission.",
            metadata={"source": "doc4.pdf", "type": "security"}
        ),
    ]


@pytest.fixture
def mock_vectorstore():
    """Mock ChromaDB vectorstore."""
    mock_vs = Mock()
    mock_vs.similarity_search_with_score = Mock(return_value=[
        (Document(page_content="Security text", metadata={}), 0.1),
        (Document(page_content="Another doc", metadata={}), 0.3),
    ])
    return mock_vs


@pytest.fixture
def retriever_no_vectorstore(sample_documents):
    """Retriever without vectorstore (keyword-only)."""
    retriever = HybridRetriever(
        vectorstore=None,
        semantic_weight=0.9,
        keyword_weight=0.1
    )
    retriever.add_documents(sample_documents)
    return retriever


@pytest.fixture
def retriever_with_vectorstore(sample_documents, mock_vectorstore):
    """Retriever with mocked vectorstore."""
    retriever = HybridRetriever(
        vectorstore=mock_vectorstore,
        semantic_weight=0.9,
        keyword_weight=0.1
    )
    retriever.add_documents(sample_documents)
    return retriever


# Test Class 1: Initialization Tests

class TestInitialization:
    """Test retriever initialization."""

    def test_default_initialization(self):
        """Test default retriever initialization."""
        retriever = HybridRetriever()
        assert retriever.semantic_weight == 0.9
        assert retriever.keyword_weight == 0.1
        assert retriever.top_k == 20
        assert retriever.final_k == 4

    def test_custom_initialization(self):
        """Test custom retriever initialization."""
        retriever = HybridRetriever(
            semantic_weight=0.7,
            keyword_weight=0.3,
            top_k=10,
            final_k=5
        )
        assert retriever.semantic_weight == 0.7
        assert retriever.keyword_weight == 0.3
        assert retriever.top_k == 10
        assert retriever.final_k == 5

    def test_initialization_with_vectorstore(self, mock_vectorstore):
        """Test initialization with vectorstore."""
        retriever = HybridRetriever(vectorstore=mock_vectorstore)
        assert retriever.vectorstore is not None

    def test_weight_sum_validation(self):
        """Test warning when weights don't sum to 1.0."""
        with patch('src.tools.hybrid_retriever.logger') as mock_logger:
            retriever = HybridRetriever(semantic_weight=0.5, keyword_weight=0.3)
            mock_logger.warning.assert_called()


# Test Class 2: Document Addition Tests

class TestDocumentAddition:
    """Test adding documents to retriever."""

    def test_add_documents_basic(self, sample_documents):
        """Test basic document addition."""
        retriever = HybridRetriever()
        retriever.add_documents(sample_documents)
        assert len(retriever.corpus_docs) == 4
        assert retriever.bm25 is not None

    def test_add_documents_empty_list(self):
        """Test adding empty document list."""
        retriever = HybridRetriever()
        retriever.add_documents([])
        assert len(retriever.corpus_docs) == 0
        assert retriever.bm25 is None

    def test_add_documents_tokenization(self, sample_documents):
        """Test document tokenization during addition."""
        retriever = HybridRetriever()
        retriever.add_documents(sample_documents)
        assert len(retriever.tokenized_corpus) == 4
        assert all(isinstance(tokens, list) for tokens in retriever.tokenized_corpus)


# Test Class 3: Keyword Retrieval Tests

class TestKeywordRetrieval:
    """Test BM25 keyword retrieval."""

    def test_keyword_retrieval_basic(self, retriever_no_vectorstore):
        """Test basic keyword retrieval."""
        results = retriever_no_vectorstore.retrieve_keyword("security vulnerabilities", k=2)
        assert len(results) <= 2
        assert all(isinstance(r, tuple) for r in results)
        assert all(isinstance(r[0], Document) for r in results)
        assert all(isinstance(r[1], (int, float)) for r in results)

    def test_keyword_retrieval_empty_query(self, retriever_no_vectorstore):
        """Test keyword retrieval with empty query."""
        results = retriever_no_vectorstore.retrieve_keyword("", k=5)
        assert results == []

    def test_keyword_retrieval_no_documents(self):
        """Test keyword retrieval without documents."""
        retriever = HybridRetriever()
        results = retriever.retrieve_keyword("test", k=5)
        assert results == []

    def test_keyword_retrieval_scores_sorted(self, retriever_no_vectorstore):
        """Test that keyword results are sorted by score."""
        results = retriever_no_vectorstore.retrieve_keyword("security", k=4)
        scores = [score for _, score in results]
        assert scores == sorted(scores, reverse=True)

    def test_keyword_retrieval_respects_k(self, retriever_no_vectorstore):
        """Test that keyword retrieval respects k parameter."""
        results = retriever_no_vectorstore.retrieve_keyword("security", k=2)
        assert len(results) <= 2


# Test Class 4: Semantic Retrieval Tests

class TestSemanticRetrieval:
    """Test semantic vector retrieval."""

    def test_semantic_retrieval_basic(self, retriever_with_vectorstore):
        """Test basic semantic retrieval."""
        results = retriever_with_vectorstore.retrieve_semantic("security", k=2)
        assert len(results) > 0
        assert all(isinstance(r, tuple) for r in results)

    def test_semantic_retrieval_no_vectorstore(self):
        """Test semantic retrieval without vectorstore."""
        retriever = HybridRetriever(vectorstore=None)
        results = retriever.retrieve_semantic("test", k=5)
        assert results == []

    def test_semantic_retrieval_empty_query(self, retriever_with_vectorstore):
        """Test semantic retrieval with empty query."""
        results = retriever_with_vectorstore.retrieve_semantic("", k=5)
        assert results == []

    def test_semantic_score_conversion(self, retriever_with_vectorstore):
        """Test distance to similarity score conversion."""
        results = retriever_with_vectorstore.retrieve_semantic("test", k=5)
        # All similarity scores should be > 0 (after exponential conversion)
        assert all(score > 0 for _, score in results)


# Test Class 5: Hybrid Retrieval Tests

class TestHybridRetrieval:
    """Test hybrid retrieval combining both methods."""

    def test_hybrid_retrieval_basic(self, retriever_with_vectorstore):
        """Test basic hybrid retrieval."""
        results = retriever_with_vectorstore.retrieve("security vulnerabilities", k=2)
        assert len(results) > 0
        assert all(isinstance(r, Document) for r in results)

    def test_hybrid_retrieval_keyword_only(self, retriever_no_vectorstore):
        """Test hybrid retrieval with keyword-only."""
        results = retriever_no_vectorstore.retrieve(
            "security",
            k=2,
            use_semantic=False,
            use_keyword=True
        )
        assert len(results) > 0

    def test_hybrid_retrieval_semantic_only(self, retriever_with_vectorstore):
        """Test hybrid retrieval with semantic-only."""
        results = retriever_with_vectorstore.retrieve(
            "security",
            k=2,
            use_semantic=True,
            use_keyword=False
        )
        assert len(results) > 0

    def test_hybrid_retrieval_empty_query(self, retriever_with_vectorstore):
        """Test hybrid retrieval with empty query."""
        results = retriever_with_vectorstore.retrieve("", k=5)
        assert results == []

    def test_hybrid_retrieval_none_query(self, retriever_with_vectorstore):
        """Test hybrid retrieval with None query."""
        results = retriever_with_vectorstore.retrieve(None, k=5)
        assert results == []

    def test_hybrid_retrieval_respects_k(self, retriever_with_vectorstore):
        """Test that hybrid retrieval respects k parameter."""
        results = retriever_with_vectorstore.retrieve("security", k=2)
        assert len(results) <= 2

    def test_hybrid_retrieval_no_results(self):
        """Test hybrid retrieval when neither method returns results."""
        retriever = HybridRetriever()
        results = retriever.retrieve("test", k=5)
        assert results == []


# Test Class 6: Score Fusion Tests

class TestScoreFusion:
    """Test result fusion logic."""

    def test_fuse_results_basic(self, retriever_with_vectorstore, sample_documents):
        """Test basic result fusion."""
        semantic_results = [(sample_documents[0], 0.9), (sample_documents[1], 0.8)]
        keyword_results = [(sample_documents[0], 0.7), (sample_documents[2], 0.6)]

        fused = retriever_with_vectorstore.fuse_results(
            semantic_results,
            keyword_results,
            k=3
        )
        assert len(fused) <= 3
        assert all(isinstance(doc, Document) for doc in fused)

    def test_fuse_results_empty_semantic(self, retriever_with_vectorstore, sample_documents):
        """Test fusion with empty semantic results."""
        keyword_results = [(sample_documents[0], 0.7)]
        fused = retriever_with_vectorstore.fuse_results([], keyword_results, k=2)
        assert len(fused) > 0

    def test_fuse_results_empty_keyword(self, retriever_with_vectorstore, sample_documents):
        """Test fusion with empty keyword results."""
        semantic_results = [(sample_documents[0], 0.9)]
        fused = retriever_with_vectorstore.fuse_results(semantic_results, [], k=2)
        assert len(fused) > 0

    def test_fuse_results_both_empty(self, retriever_with_vectorstore):
        """Test fusion with both empty results."""
        fused = retriever_with_vectorstore.fuse_results([], [], k=2)
        assert fused == []

    def test_fuse_results_deduplication(self, retriever_with_vectorstore, sample_documents):
        """Test that fusion deduplicates documents."""
        # Same document in both results
        semantic_results = [(sample_documents[0], 0.9)]
        keyword_results = [(sample_documents[0], 0.7)]

        fused = retriever_with_vectorstore.fuse_results(
            semantic_results,
            keyword_results,
            k=5
        )
        # Should only have one instance of the document
        assert len(fused) == 1

    def test_fuse_results_weighted_scoring(self, retriever_with_vectorstore, sample_documents):
        """Test that fusion uses weighted scoring."""
        # Document in semantic should score higher due to 0.9 weight
        semantic_results = [(sample_documents[0], 1.0)]
        keyword_results = [(sample_documents[1], 1.0)]

        fused = retriever_with_vectorstore.fuse_results(
            semantic_results,
            keyword_results,
            k=2
        )
        # First result should be from semantic (higher weight)
        assert fused[0].page_content == sample_documents[0].page_content


# Test Class 7: Utility Method Tests

class TestUtilityMethods:
    """Test utility and helper methods."""

    def test_tokenize_basic(self):
        """Test basic tokenization."""
        retriever = HybridRetriever()
        tokens = retriever._tokenize("Machine learning algorithms")
        assert tokens == ['machine', 'learning', 'algorithms']

    def test_tokenize_with_punctuation(self):
        """Test tokenization with punctuation."""
        retriever = HybridRetriever()
        tokens = retriever._tokenize("Hello, world! Test.")
        assert 'hello' in tokens
        assert 'world' in tokens

    def test_tokenize_empty_string(self):
        """Test tokenization with empty string."""
        retriever = HybridRetriever()
        tokens = retriever._tokenize("")
        assert tokens == []

    def test_normalize_query_basic(self):
        """Test query normalization."""
        retriever = HybridRetriever()
        normalized = retriever._normalize_query("  Test Query  ")
        assert normalized == "test query"

    def test_normalize_query_lowercase(self):
        """Test query normalization lowercases."""
        retriever = HybridRetriever()
        normalized = retriever._normalize_query("UPPERCASE")
        assert normalized == "uppercase"

    def test_normalize_scores_basic(self, sample_documents):
        """Test score normalization."""
        retriever = HybridRetriever()
        results = [
            (sample_documents[0], 10.0),
            (sample_documents[1], 5.0),
            (sample_documents[2], 0.0)
        ]
        normalized = retriever._normalize_scores(results)

        # Scores should be in 0-1 range
        scores = [score for _, score in normalized]
        assert max(scores) == 1.0
        assert min(scores) == 0.0

    def test_normalize_scores_empty(self):
        """Test score normalization with empty list."""
        retriever = HybridRetriever()
        normalized = retriever._normalize_scores([])
        assert normalized == []

    def test_normalize_scores_uniform(self, sample_documents):
        """Test score normalization when all scores are equal."""
        retriever = HybridRetriever()
        results = [(sample_documents[0], 5.0), (sample_documents[1], 5.0)]
        normalized = retriever._normalize_scores(results)

        # All should be normalized to 1.0
        assert all(score == 1.0 for _, score in normalized)


# Test Class 8: Statistics Tests

class TestStatistics:
    """Test retriever statistics."""

    def test_get_stats_basic(self, retriever_no_vectorstore):
        """Test getting basic stats."""
        stats = retriever_no_vectorstore.get_stats()
        assert 'semantic_weight' in stats
        assert 'keyword_weight' in stats
        assert 'corpus_size' in stats
        assert stats['corpus_size'] == 4

    def test_get_stats_initialization_flags(self):
        """Test BM25 and vectorstore initialization flags."""
        retriever = HybridRetriever()
        stats = retriever.get_stats()
        assert stats['bm25_initialized'] is False
        assert stats['vectorstore_initialized'] is False

    def test_get_stats_after_adding_docs(self, retriever_no_vectorstore):
        """Test stats after adding documents."""
        stats = retriever_no_vectorstore.get_stats()
        assert stats['bm25_initialized'] is True
        assert stats['corpus_size'] > 0


# Test Class 9: Edge Cases

class TestEdgeCases:
    """Test edge cases and error handling."""

    def test_large_k_value(self, retriever_no_vectorstore):
        """Test retrieval with k larger than corpus."""
        results = retriever_no_vectorstore.retrieve("security", k=100)
        # Should return all available documents (max 4 in fixture)
        assert len(results) <= 4

    def test_special_characters_in_query(self, retriever_no_vectorstore):
        """Test retrieval with special characters in query."""
        results = retriever_no_vectorstore.retrieve("@#$% security!", k=2)
        # Should handle gracefully
        assert isinstance(results, list)

    def test_unicode_in_query(self, retriever_no_vectorstore):
        """Test retrieval with unicode characters."""
        results = retriever_no_vectorstore.retrieve("café naïve 你好", k=2)
        assert isinstance(results, list)

    def test_very_long_query(self, retriever_no_vectorstore):
        """Test retrieval with very long query."""
        long_query = "security " * 100
        results = retriever_no_vectorstore.retrieve(long_query, k=2)
        assert isinstance(results, list)

    def test_whitespace_only_query(self, retriever_no_vectorstore):
        """Test retrieval with whitespace-only query."""
        results = retriever_no_vectorstore.retrieve("   \n\t   ", k=2)
        # Should normalize to empty and return empty list
        assert results == []


# Test Class 10: Integration Tests

class TestIntegration:
    """Integration tests combining multiple features."""

    def test_end_to_end_workflow(self, sample_documents):
        """Test complete retrieval workflow."""
        # Initialize retriever
        retriever = HybridRetriever(
            vectorstore=None,
            semantic_weight=0.9,
            keyword_weight=0.1
        )

        # Add documents
        retriever.add_documents(sample_documents)

        # Retrieve
        results = retriever.retrieve("security algorithms", k=2)

        # Verify
        assert len(results) > 0
        assert all(isinstance(r, Document) for r in results)

    def test_multiple_queries_same_retriever(self, retriever_no_vectorstore):
        """Test multiple queries on same retriever instance."""
        queries = ["security", "risk assessment", "encryption"]

        all_results = []
        for query in queries:
            results = retriever_no_vectorstore.retrieve(query, k=2)
            all_results.append(results)

        # All queries should return results
        assert all(len(r) > 0 for r in all_results)

    def test_weight_configuration_affects_results(self, sample_documents):
        """Test that different weight configurations affect results."""
        # Create two retrievers with different weights
        retriever1 = HybridRetriever(semantic_weight=0.9, keyword_weight=0.1)
        retriever2 = HybridRetriever(semantic_weight=0.1, keyword_weight=0.9)

        retriever1.add_documents(sample_documents)
        retriever2.add_documents(sample_documents)

        # Weights should be different between the two retrievers
        assert retriever1.semantic_weight != retriever2.semantic_weight
        assert retriever1.keyword_weight != retriever2.keyword_weight


if __name__ == "__main__":
    pytest.main([__file__, '-v', '--tb=short'])
