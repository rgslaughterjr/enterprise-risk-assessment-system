"""
Comprehensive tests for SemanticChunker

Tests cover all 5 chunking strategies plus edge cases and error handling.
Target: 30+ tests with 100% pass rate

Author: Enterprise Risk Assessment System
Date: 2025-11-15
Week: 7 Session 1 - Advanced RAG Foundation
"""

import pytest
from unittest.mock import Mock, patch
from langchain_core.documents import Document
from src.tools.semantic_chunker import SemanticChunker


# Fixtures

@pytest.fixture
def chunker():
    """Standard chunker instance."""
    return SemanticChunker(default_chunk_size=100, default_overlap=20)


@pytest.fixture
def sample_text():
    """Sample text for testing."""
    return """This is the first sentence. This is the second sentence. This is the third sentence.

This is a new paragraph. It has multiple sentences. This continues the paragraph.

Another paragraph here. With more content. And even more text."""


@pytest.fixture
def long_text():
    """Long text for testing size-based chunking."""
    return "Word " * 500  # 2500+ characters


@pytest.fixture
def sample_document():
    """Sample Document object."""
    return Document(
        page_content="Test content for document chunking. More sentences here.",
        metadata={"source": "test.pdf", "page": 1}
    )


# Test Class 1: Initialization Tests

class TestInitialization:
    """Test chunker initialization."""

    def test_default_initialization(self):
        """Test default chunker initialization."""
        chunker = SemanticChunker()
        assert chunker.default_chunk_size == 1000
        assert chunker.default_overlap == 200

    def test_custom_initialization(self):
        """Test custom chunker initialization."""
        chunker = SemanticChunker(default_chunk_size=500, default_overlap=50)
        assert chunker.default_chunk_size == 500
        assert chunker.default_overlap == 50

    def test_initialization_with_zero_values(self):
        """Test initialization with edge case values."""
        chunker = SemanticChunker(default_chunk_size=0, default_overlap=0)
        assert chunker.default_chunk_size == 0
        assert chunker.default_overlap == 0


# Test Class 2: Fixed-Size Chunking Tests

class TestFixedSizeChunking:
    """Test fixed-size chunking strategy."""

    def test_basic_fixed_chunking(self, chunker, sample_text):
        """Test basic fixed-size chunking."""
        chunks = chunker.chunk_by_fixed_size(sample_text, chunk_size=50, overlap=10)
        assert len(chunks) > 0
        assert all(isinstance(c, Document) for c in chunks)
        assert all(c.metadata['chunk_strategy'] == 'fixed_size' for c in chunks)

    def test_fixed_chunking_respects_size(self, chunker):
        """Test that chunks respect size limits."""
        text = "A" * 200
        chunks = chunker.chunk_by_fixed_size(text, chunk_size=50, overlap=0)
        assert len(chunks) == 4
        assert all(len(c.page_content) <= 50 for c in chunks)

    def test_fixed_chunking_with_overlap(self, chunker):
        """Test overlap in fixed-size chunking."""
        text = "ABCDEFGHIJ" * 10  # 100 chars
        chunks = chunker.chunk_by_fixed_size(text, chunk_size=30, overlap=10)
        assert len(chunks) > 1
        # Check overlap exists
        assert chunks[0].metadata['overlap'] == 10

    def test_fixed_chunking_empty_text(self, chunker):
        """Test fixed chunking with empty text."""
        chunks = chunker.chunk_by_fixed_size("")
        assert chunks == []

    def test_fixed_chunking_none_text(self, chunker):
        """Test fixed chunking with None text."""
        chunks = chunker.chunk_by_fixed_size(None)
        assert chunks == []

    def test_fixed_chunking_invalid_chunk_size(self, chunker, sample_text):
        """Test fixed chunking with invalid chunk size."""
        chunks = chunker.chunk_by_fixed_size(sample_text, chunk_size=0)
        assert chunks == []

    def test_fixed_chunking_overlap_too_large(self, chunker, sample_text):
        """Test fixed chunking when overlap >= chunk_size."""
        chunks = chunker.chunk_by_fixed_size(sample_text, chunk_size=50, overlap=60)
        # Should auto-adjust overlap
        assert len(chunks) > 0

    def test_fixed_chunking_metadata(self, chunker, sample_text):
        """Test metadata in fixed-size chunks."""
        custom_meta = {"source": "test.pdf"}
        chunks = chunker.chunk_by_fixed_size(sample_text, metadata=custom_meta)
        assert all(c.metadata.get('source') == 'test.pdf' for c in chunks)
        assert all('chunk_id' in c.metadata for c in chunks)


# Test Class 3: Sentence-Based Chunking Tests

class TestSentenceChunking:
    """Test sentence-based chunking strategy."""

    def test_basic_sentence_chunking(self, chunker, sample_text):
        """Test basic sentence chunking."""
        chunks = chunker.chunk_by_sentences(sample_text, max_sentences=2)
        assert len(chunks) > 0
        assert all(c.metadata['chunk_strategy'] == 'sentence_based' for c in chunks)

    def test_sentence_count_limit(self, chunker):
        """Test sentence count limits."""
        text = "One. Two. Three. Four. Five. Six."
        chunks = chunker.chunk_by_sentences(text, max_sentences=2)
        assert len(chunks) == 3

    def test_sentence_chunking_preserves_content(self, chunker):
        """Test that sentence chunking preserves all content."""
        text = "First sentence. Second sentence. Third sentence."
        chunks = chunker.chunk_by_sentences(text, max_sentences=10)
        combined = ' '.join([c.page_content for c in chunks])
        assert "First sentence" in combined
        assert "Second sentence" in combined
        assert "Third sentence" in combined

    def test_sentence_chunking_empty_text(self, chunker):
        """Test sentence chunking with empty text."""
        chunks = chunker.chunk_by_sentences("")
        assert chunks == []

    def test_sentence_chunking_invalid_max_sentences(self, chunker, sample_text):
        """Test sentence chunking with invalid max_sentences."""
        chunks = chunker.chunk_by_sentences(sample_text, max_sentences=0)
        assert chunks == []

    def test_sentence_chunking_with_metadata(self, chunker, sample_text):
        """Test metadata in sentence-based chunks."""
        custom_meta = {"doc_type": "report"}
        chunks = chunker.chunk_by_sentences(sample_text, metadata=custom_meta)
        assert all(c.metadata.get('doc_type') == 'report' for c in chunks)

    def test_sentence_chunking_question_marks(self, chunker):
        """Test sentence splitting with question marks."""
        text = "What is this? Another question? Final statement."
        chunks = chunker.chunk_by_sentences(text, max_sentences=1)
        assert len(chunks) == 3

    def test_sentence_chunking_exclamations(self, chunker):
        """Test sentence splitting with exclamation marks."""
        text = "Alert! Warning! All clear."
        chunks = chunker.chunk_by_sentences(text, max_sentences=1)
        assert len(chunks) == 3


# Test Class 4: Paragraph-Based Chunking Tests

class TestParagraphChunking:
    """Test paragraph-based chunking strategy."""

    def test_basic_paragraph_chunking(self, chunker, sample_text):
        """Test basic paragraph chunking."""
        chunks = chunker.chunk_by_paragraphs(sample_text)
        assert len(chunks) == 3  # sample_text has 3 paragraphs
        assert all(c.metadata['chunk_strategy'] == 'paragraph_based' for c in chunks)

    def test_paragraph_chunking_single_paragraph(self, chunker):
        """Test paragraph chunking with single paragraph."""
        text = "Single paragraph without breaks."
        chunks = chunker.chunk_by_paragraphs(text)
        assert len(chunks) == 1

    def test_paragraph_chunking_empty_text(self, chunker):
        """Test paragraph chunking with empty text."""
        chunks = chunker.chunk_by_paragraphs("")
        assert chunks == []

    def test_paragraph_chunking_multiple_newlines(self, chunker):
        """Test paragraph splitting with multiple newlines."""
        text = "Para 1\n\n\nPara 2\n\n\n\nPara 3"
        chunks = chunker.chunk_by_paragraphs(text)
        assert len(chunks) == 3

    def test_paragraph_chunking_with_metadata(self, chunker, sample_text):
        """Test metadata in paragraph-based chunks."""
        custom_meta = {"section": "intro"}
        chunks = chunker.chunk_by_paragraphs(sample_text, metadata=custom_meta)
        assert all(c.metadata.get('section') == 'intro' for c in chunks)

    def test_paragraph_metadata_char_count(self, chunker, sample_text):
        """Test char_count in paragraph metadata."""
        chunks = chunker.chunk_by_paragraphs(sample_text)
        assert all('char_count' in c.metadata for c in chunks)
        assert all(c.metadata['char_count'] > 0 for c in chunks)


# Test Class 5: Semantic Similarity Chunking Tests

class TestSemanticChunking:
    """Test semantic similarity chunking strategy."""

    def test_basic_semantic_chunking(self, chunker, sample_text):
        """Test basic semantic chunking."""
        chunks = chunker.chunk_by_semantic_similarity(sample_text, threshold=0.5)
        assert len(chunks) > 0
        assert all(c.metadata['chunk_strategy'] == 'semantic_similarity' for c in chunks)

    def test_semantic_chunking_with_different_thresholds(self, chunker, sample_text):
        """Test semantic chunking with varying thresholds."""
        low_chunks = chunker.chunk_by_semantic_similarity(sample_text, threshold=0.1)
        high_chunks = chunker.chunk_by_semantic_similarity(sample_text, threshold=0.9)
        # Lower threshold should create more chunks
        assert len(high_chunks) >= len(low_chunks)

    def test_semantic_chunking_single_sentence(self, chunker):
        """Test semantic chunking with single sentence."""
        text = "Only one sentence here."
        chunks = chunker.chunk_by_semantic_similarity(text)
        assert len(chunks) == 1

    def test_semantic_chunking_empty_text(self, chunker):
        """Test semantic chunking with empty text."""
        chunks = chunker.chunk_by_semantic_similarity("")
        assert chunks == []

    def test_semantic_chunking_invalid_threshold(self, chunker, sample_text):
        """Test semantic chunking with invalid threshold."""
        chunks = chunker.chunk_by_semantic_similarity(sample_text, threshold=1.5)
        assert chunks == []

    def test_semantic_chunking_metadata(self, chunker, sample_text):
        """Test metadata in semantic chunks."""
        chunks = chunker.chunk_by_semantic_similarity(sample_text, threshold=0.5)
        assert all('threshold' in c.metadata for c in chunks)
        assert all(c.metadata['threshold'] == 0.5 for c in chunks)

    def test_semantic_chunking_window_size(self, chunker, sample_text):
        """Test semantic chunking with custom window size."""
        chunks = chunker.chunk_by_semantic_similarity(sample_text, window_size=2)
        assert len(chunks) > 0


# Test Class 6: Hybrid Chunking Tests

class TestHybridChunking:
    """Test hybrid chunking strategy."""

    def test_basic_hybrid_chunking(self, chunker, sample_text):
        """Test basic hybrid chunking."""
        chunks = chunker.chunk_hybrid(sample_text, strategy='semantic', max_size=100)
        assert len(chunks) > 0
        assert all('hybrid' in c.metadata['chunk_strategy'] for c in chunks)

    def test_hybrid_semantic_strategy(self, chunker, sample_text):
        """Test hybrid with semantic base strategy."""
        chunks = chunker.chunk_hybrid(sample_text, strategy='semantic', max_size=200)
        assert len(chunks) > 0
        assert all(c.metadata.get('base_strategy') == 'semantic' for c in chunks)

    def test_hybrid_sentence_strategy(self, chunker, sample_text):
        """Test hybrid with sentence base strategy."""
        chunks = chunker.chunk_hybrid(sample_text, strategy='sentence', max_size=200)
        assert len(chunks) > 0
        assert all(c.metadata.get('base_strategy') == 'sentence' for c in chunks)

    def test_hybrid_paragraph_strategy(self, chunker, sample_text):
        """Test hybrid with paragraph base strategy."""
        chunks = chunker.chunk_hybrid(sample_text, strategy='paragraph', max_size=200)
        assert len(chunks) > 0
        assert all(c.metadata.get('base_strategy') == 'paragraph' for c in chunks)

    def test_hybrid_respects_max_size(self, chunker, long_text):
        """Test that hybrid chunking respects max size."""
        chunks = chunker.chunk_hybrid(long_text, strategy='semantic', max_size=300)
        assert all(len(c.page_content) <= 300 for c in chunks)

    def test_hybrid_invalid_strategy(self, chunker, sample_text):
        """Test hybrid with invalid strategy."""
        chunks = chunker.chunk_hybrid(sample_text, strategy='invalid')
        assert chunks == []

    def test_hybrid_empty_text(self, chunker):
        """Test hybrid chunking with empty text."""
        chunks = chunker.chunk_hybrid("")
        assert chunks == []

    def test_hybrid_with_metadata(self, chunker, sample_text):
        """Test metadata in hybrid chunks."""
        custom_meta = {"type": "hybrid_test"}
        chunks = chunker.chunk_hybrid(sample_text, metadata=custom_meta)
        assert all(c.metadata.get('type') == 'hybrid_test' for c in chunks)

    def test_hybrid_min_size_constraint(self, chunker):
        """Test hybrid chunking with min size constraint."""
        text = "A. B. C. D. E. F."
        chunks = chunker.chunk_hybrid(text, strategy='sentence', max_size=100, min_size=10)
        assert len(chunks) > 0


# Test Class 7: Document Chunking Tests

class TestDocumentChunking:
    """Test convenience document chunking method."""

    def test_chunk_document_basic(self, chunker, sample_document):
        """Test basic document chunking."""
        chunks = chunker.chunk_document(sample_document, strategy='fixed')
        assert len(chunks) > 0
        assert all(isinstance(c, Document) for c in chunks)

    def test_chunk_document_preserves_metadata(self, chunker, sample_document):
        """Test that document chunking preserves original metadata."""
        chunks = chunker.chunk_document(sample_document, strategy='sentence')
        assert all(c.metadata.get('source') == 'test.pdf' for c in chunks)
        assert all(c.metadata.get('page') == 1 for c in chunks)

    def test_chunk_document_all_strategies(self, chunker, sample_document):
        """Test document chunking with all strategies."""
        strategies = ['fixed', 'sentence', 'paragraph', 'semantic', 'hybrid']
        for strategy in strategies:
            chunks = chunker.chunk_document(sample_document, strategy=strategy)
            assert len(chunks) > 0

    def test_chunk_document_invalid_strategy(self, chunker, sample_document):
        """Test document chunking with invalid strategy."""
        chunks = chunker.chunk_document(sample_document, strategy='invalid')
        assert chunks == []

    def test_chunk_document_none_document(self, chunker):
        """Test document chunking with None document."""
        chunks = chunker.chunk_document(None)
        assert chunks == []


# Test Class 8: Helper Methods Tests

class TestHelperMethods:
    """Test internal helper methods."""

    def test_tokenize_basic(self, chunker):
        """Test basic tokenization."""
        tokens = chunker._tokenize("Hello world test")
        assert tokens == ['hello', 'world', 'test']

    def test_tokenize_with_punctuation(self, chunker):
        """Test tokenization with punctuation."""
        tokens = chunker._tokenize("Hello, world! Test.")
        assert tokens == ['hello', 'world', 'test']

    def test_tokenize_empty_string(self, chunker):
        """Test tokenization with empty string."""
        tokens = chunker._tokenize("")
        assert tokens == []

    def test_tokenize_numbers(self, chunker):
        """Test tokenization with numbers."""
        tokens = chunker._tokenize("Test 123 value")
        assert '123' in tokens


# Test Class 9: Edge Cases and Error Handling

class TestEdgeCases:
    """Test edge cases and error handling."""

    def test_very_long_text(self, chunker, long_text):
        """Test chunking with very long text."""
        chunks = chunker.chunk_by_fixed_size(long_text, chunk_size=500)
        assert len(chunks) > 0
        total_length = sum(len(c.page_content) for c in chunks)
        assert total_length > 0

    def test_special_characters(self, chunker):
        """Test chunking with special characters."""
        text = "Test @#$% special & characters! Works?"
        chunks = chunker.chunk_by_sentences(text)
        assert len(chunks) > 0

    def test_unicode_text(self, chunker):
        """Test chunking with unicode characters."""
        text = "Testing unicode: café, naïve, 你好"
        chunks = chunker.chunk_by_fixed_size(text, chunk_size=50)
        assert len(chunks) > 0

    def test_whitespace_only(self, chunker):
        """Test chunking with whitespace-only text."""
        text = "   \n\n   \t\t   "
        chunks = chunker.chunk_by_paragraphs(text)
        assert chunks == []

    def test_single_word(self, chunker):
        """Test chunking with single word."""
        text = "Word"
        chunks = chunker.chunk_by_sentences(text)
        assert len(chunks) > 0


# Test Class 10: Integration Tests

class TestIntegration:
    """Integration tests combining multiple features."""

    def test_all_strategies_same_text(self, chunker, sample_text):
        """Test all chunking strategies on same text."""
        strategies = {
            'fixed': lambda: chunker.chunk_by_fixed_size(sample_text),
            'sentence': lambda: chunker.chunk_by_sentences(sample_text),
            'paragraph': lambda: chunker.chunk_by_paragraphs(sample_text),
            'semantic': lambda: chunker.chunk_by_semantic_similarity(sample_text),
            'hybrid': lambda: chunker.chunk_hybrid(sample_text)
        }

        results = {}
        for name, func in strategies.items():
            chunks = func()
            assert len(chunks) > 0, f"{name} strategy failed"
            results[name] = len(chunks)

        # All strategies should produce chunks
        assert all(count > 0 for count in results.values())

    def test_metadata_consistency(self, chunker, sample_text):
        """Test metadata consistency across strategies."""
        custom_meta = {"test": "value", "number": 42}

        strategies_with_meta = [
            chunker.chunk_by_fixed_size(sample_text, metadata=custom_meta),
            chunker.chunk_by_sentences(sample_text, metadata=custom_meta),
            chunker.chunk_by_paragraphs(sample_text, metadata=custom_meta),
            chunker.chunk_by_semantic_similarity(sample_text, metadata=custom_meta),
            chunker.chunk_hybrid(sample_text, metadata=custom_meta)
        ]

        for chunks in strategies_with_meta:
            assert all(c.metadata.get('test') == 'value' for c in chunks)
            assert all(c.metadata.get('number') == 42 for c in chunks)

    def test_chunk_id_sequence(self, chunker, sample_text):
        """Test that chunk IDs are sequential."""
        chunks = chunker.chunk_by_fixed_size(sample_text, chunk_size=50)
        chunk_ids = [c.metadata['chunk_id'] for c in chunks]
        assert chunk_ids == list(range(len(chunks)))


if __name__ == "__main__":
    pytest.main([__file__, '-v', '--tb=short'])
