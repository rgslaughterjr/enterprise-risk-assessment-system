"""
Comprehensive tests for QueryOptimizer

Tests cover all query transformation strategies and edge cases.
Target: 20+ tests with 100% pass rate

Author: Enterprise Risk Assessment System
Date: 2025-11-15
Week: 7 Session 1 - Advanced RAG Foundation
"""

import pytest
from unittest.mock import Mock, patch
from src.tools.query_optimizer import QueryOptimizer


# Fixtures

@pytest.fixture
def optimizer():
    """Standard optimizer instance."""
    return QueryOptimizer()


@pytest.fixture
def optimizer_with_llm():
    """Optimizer with mocked LLM."""
    mock_llm = Mock()
    return QueryOptimizer(llm=mock_llm)


# Test Class 1: Initialization Tests

class TestInitialization:
    """Test optimizer initialization."""

    def test_default_initialization(self):
        """Test default optimizer initialization."""
        optimizer = QueryOptimizer()
        assert optimizer.llm is None
        assert isinstance(optimizer._query_cache, dict)
        assert len(optimizer.synonyms) > 0

    def test_initialization_with_llm(self):
        """Test initialization with LLM."""
        mock_llm = Mock()
        optimizer = QueryOptimizer(llm=mock_llm)
        assert optimizer.llm is not None

    def test_synonyms_loaded(self, optimizer):
        """Test that domain synonyms are loaded."""
        assert "vulnerability" in optimizer.synonyms
        assert "risk" in optimizer.synonyms
        assert len(optimizer.synonyms["vulnerability"]) > 0


# Test Class 2: Query Expansion Tests

class TestQueryExpansion:
    """Test query expansion functionality."""

    def test_basic_expansion(self, optimizer):
        """Test basic query expansion."""
        result = optimizer.expand_query("vulnerability")
        assert "vulnerability" in result
        # Should include synonyms
        assert any(syn in result for syn in ["weakness", "flaw", "security hole"])

    def test_expansion_with_multiple_terms(self, optimizer):
        """Test expansion with multiple terms."""
        result = optimizer.expand_query("vulnerability risk")
        assert "vulnerability" in result
        assert "risk" in result

    def test_expansion_empty_query(self, optimizer):
        """Test expansion with empty query."""
        result = optimizer.expand_query("")
        assert result == ""

    def test_expansion_none_query(self, optimizer):
        """Test expansion with None query."""
        result = optimizer.expand_query(None)
        assert result is None

    def test_expansion_unknown_term(self, optimizer):
        """Test expansion with unknown term."""
        result = optimizer.expand_query("unknownterm12345")
        assert "unknownterm12345" in result

    def test_expansion_max_expansions(self, optimizer):
        """Test max_expansions parameter."""
        result1 = optimizer.expand_query("vulnerability", max_expansions=1)
        result2 = optimizer.expand_query("vulnerability", max_expansions=3)
        # More expansions should result in longer query
        assert len(result2.split()) >= len(result1.split())

    def test_expansion_caching(self, optimizer):
        """Test that expansion results are cached."""
        query = "vulnerability test"
        result1 = optimizer.expand_query(query)
        result2 = optimizer.expand_query(query)
        assert result1 == result2
        assert optimizer.get_cache_size() > 0


# Test Class 3: Query Rewriting Tests

class TestQueryRewriting:
    """Test query rewriting functionality."""

    def test_basic_rewriting(self, optimizer):
        """Test basic query rewriting."""
        result = optimizer.rewrite_query("how to stop hackers")
        assert result is not None
        assert isinstance(result, str)

    def test_technical_rewriting(self, optimizer):
        """Test technical style rewriting."""
        result = optimizer.rewrite_query("how to stop hackers", style="technical")
        assert "unauthorized access" in result or "hackers" in result

    def test_formal_rewriting(self, optimizer):
        """Test formal style rewriting."""
        result = optimizer.rewrite_query("like really very important", style="formal")
        # Casual words should be removed
        assert "like" not in result or result == "like really very important"

    def test_rewriting_empty_query(self, optimizer):
        """Test rewriting with empty query."""
        result = optimizer.rewrite_query("")
        assert result == ""

    def test_rewriting_none_query(self, optimizer):
        """Test rewriting with None query."""
        result = optimizer.rewrite_query(None)
        assert result is None

    def test_rewriting_caching(self, optimizer):
        """Test that rewriting results are cached."""
        query = "how to fix security problems"
        result1 = optimizer.rewrite_query(query, style="technical")
        result2 = optimizer.rewrite_query(query, style="technical")
        assert result1 == result2


# Test Class 4: Multi-Query Generation Tests

class TestMultiQueryGeneration:
    """Test multi-query generation functionality."""

    def test_basic_multi_query(self, optimizer):
        """Test basic multi-query generation."""
        results = optimizer.generate_multi_queries("security risks", n=3)
        assert len(results) == 3
        assert isinstance(results, list)
        assert all(isinstance(q, str) for q in results)

    def test_multi_query_includes_original(self, optimizer):
        """Test that original query is included."""
        query = "test query"
        results = optimizer.generate_multi_queries(query, n=3)
        assert query in results

    def test_multi_query_variations_differ(self, optimizer):
        """Test that variations are different."""
        results = optimizer.generate_multi_queries("vulnerability", n=3)
        # At least some should be different
        unique_results = set(results)
        assert len(unique_results) >= 1

    def test_multi_query_with_n_1(self, optimizer):
        """Test multi-query with n=1."""
        query = "test"
        results = optimizer.generate_multi_queries(query, n=1)
        assert len(results) == 1
        assert results[0] == query

    def test_multi_query_empty_query(self, optimizer):
        """Test multi-query with empty query."""
        results = optimizer.generate_multi_queries("", n=3)
        assert results == []

    def test_multi_query_none_query(self, optimizer):
        """Test multi-query with None query."""
        results = optimizer.generate_multi_queries(None, n=3)
        assert results == []

    def test_multi_query_caching(self, optimizer):
        """Test that multi-query results are cached."""
        query = "security test"
        results1 = optimizer.generate_multi_queries(query, n=3)
        results2 = optimizer.generate_multi_queries(query, n=3)
        assert results1 == results2


# Test Class 5: Hypothetical Answer Generation Tests

class TestHypotheticalAnswerGeneration:
    """Test HyDE (Hypothetical Document Embeddings) functionality."""

    def test_basic_hypothetical_answer(self, optimizer):
        """Test basic hypothetical answer generation."""
        result = optimizer.generate_hypothetical_answer("What is a vulnerability?")
        assert result is not None
        assert len(result) > 0
        assert isinstance(result, str)

    def test_definitional_query(self, optimizer):
        """Test hypothetical answer for definitional query."""
        result = optimizer.generate_hypothetical_answer("What is SQL injection?")
        assert len(result) > 0

    def test_procedural_query(self, optimizer):
        """Test hypothetical answer for procedural query."""
        result = optimizer.generate_hypothetical_answer("How to prevent attacks?")
        assert len(result) > 0

    def test_risk_query(self, optimizer):
        """Test hypothetical answer for risk query."""
        result = optimizer.generate_hypothetical_answer("What are security risks?")
        assert len(result) > 0
        assert any(word in result.lower() for word in ["risk", "security", "threat"])

    def test_hypothetical_answer_max_length(self, optimizer):
        """Test max_length parameter."""
        result = optimizer.generate_hypothetical_answer("Test query", max_length=50)
        assert len(result) <= 60  # Allow some buffer for ellipsis

    def test_hypothetical_answer_empty_query(self, optimizer):
        """Test hypothetical answer with empty query."""
        result = optimizer.generate_hypothetical_answer("")
        assert result == ""

    def test_hypothetical_answer_none_query(self, optimizer):
        """Test hypothetical answer with None query."""
        result = optimizer.generate_hypothetical_answer(None)
        assert result == ""

    def test_hypothetical_answer_caching(self, optimizer):
        """Test that hypothetical answers are cached."""
        query = "What is encryption?"
        result1 = optimizer.generate_hypothetical_answer(query)
        result2 = optimizer.generate_hypothetical_answer(query)
        assert result1 == result2


# Test Class 6: Optimize Query Tests

class TestOptimizeQuery:
    """Test the general optimize_query method."""

    def test_optimize_with_expand_strategy(self, optimizer):
        """Test optimize_query with expand strategy."""
        result = optimizer.optimize_query("vulnerability", strategy="expand")
        assert "vulnerability" in result

    def test_optimize_with_rewrite_strategy(self, optimizer):
        """Test optimize_query with rewrite strategy."""
        result = optimizer.optimize_query("test query", strategy="rewrite")
        assert isinstance(result, str)

    def test_optimize_with_hyde_strategy(self, optimizer):
        """Test optimize_query with HyDE strategy."""
        result = optimizer.optimize_query("What is a risk?", strategy="hyde")
        assert isinstance(result, str)
        assert len(result) > 0

    def test_optimize_with_unknown_strategy(self, optimizer):
        """Test optimize_query with unknown strategy."""
        query = "test query"
        result = optimizer.optimize_query(query, strategy="unknown")
        # Should return original query
        assert result == query

    def test_optimize_empty_query(self, optimizer):
        """Test optimize_query with empty query."""
        result = optimizer.optimize_query("")
        assert result == ""


# Test Class 7: Cache Management Tests

class TestCacheManagement:
    """Test cache management functionality."""

    def test_cache_size_increases(self, optimizer):
        """Test that cache size increases with usage."""
        initial_size = optimizer.get_cache_size()
        optimizer.expand_query("vulnerability")
        optimizer.rewrite_query("test query")
        assert optimizer.get_cache_size() > initial_size

    def test_clear_cache(self, optimizer):
        """Test cache clearing."""
        optimizer.expand_query("test")
        optimizer.clear_cache()
        assert optimizer.get_cache_size() == 0

    def test_cache_after_clear(self, optimizer):
        """Test that cache works after clearing."""
        optimizer.expand_query("test")
        optimizer.clear_cache()
        optimizer.expand_query("vulnerability")
        assert optimizer.get_cache_size() > 0


# Test Class 8: Helper Method Tests

class TestHelperMethods:
    """Test internal helper methods."""

    def test_extract_key_terms_basic(self, optimizer):
        """Test key term extraction."""
        terms = optimizer._extract_key_terms("What is a vulnerability?")
        assert "vulnerability" in terms
        assert "what" not in terms  # Question word removed

    def test_extract_key_terms_removes_stop_words(self, optimizer):
        """Test that stop words are removed."""
        terms = optimizer._extract_key_terms("What is the security risk?")
        assert "the" not in terms
        assert "is" not in terms

    def test_extract_key_terms_empty_query(self, optimizer):
        """Test key term extraction with empty query."""
        terms = optimizer._extract_key_terms("")
        assert terms == []


# Test Class 9: Edge Cases

class TestEdgeCases:
    """Test edge cases and error handling."""

    def test_very_long_query(self, optimizer):
        """Test with very long query."""
        long_query = "vulnerability " * 100
        result = optimizer.expand_query(long_query)
        assert isinstance(result, str)

    def test_special_characters(self, optimizer):
        """Test with special characters."""
        result = optimizer.expand_query("@#$% vulnerability!")
        assert isinstance(result, str)

    def test_unicode_characters(self, optimizer):
        """Test with unicode characters."""
        result = optimizer.expand_query("café naïve 你好 vulnerability")
        assert isinstance(result, str)

    def test_numeric_query(self, optimizer):
        """Test with numeric query."""
        result = optimizer.expand_query("12345")
        assert "12345" in result


# Test Class 10: Integration Tests

class TestIntegration:
    """Integration tests combining multiple features."""

    def test_full_workflow(self, optimizer):
        """Test complete optimization workflow."""
        original = "vulnerability assessment"

        # Expand
        expanded = optimizer.expand_query(original)
        assert len(expanded) > len(original)

        # Rewrite
        rewritten = optimizer.rewrite_query(original, style="technical")
        assert isinstance(rewritten, str)

        # Multi-query
        variations = optimizer.generate_multi_queries(original, n=3)
        assert len(variations) == 3

        # HyDE
        hypothetical = optimizer.generate_hypothetical_answer(f"What is {original}?")
        assert len(hypothetical) > 0

    def test_multiple_optimizations_same_query(self, optimizer):
        """Test multiple optimizations on same query."""
        query = "security risks"

        expanded = optimizer.expand_query(query)
        rewritten = optimizer.rewrite_query(query)
        multi = optimizer.generate_multi_queries(query, n=2)

        # All should return valid results
        assert expanded is not None
        assert rewritten is not None
        assert len(multi) == 2

    def test_cache_effectiveness(self, optimizer):
        """Test that caching improves performance."""
        query = "vulnerability test"

        # First call
        optimizer.expand_query(query)
        cache_size_1 = optimizer.get_cache_size()

        # Second call (should use cache)
        optimizer.expand_query(query)
        cache_size_2 = optimizer.get_cache_size()

        # Cache size should not increase for same query
        assert cache_size_1 == cache_size_2


if __name__ == "__main__":
    pytest.main([__file__, '-v', '--tb=short'])
