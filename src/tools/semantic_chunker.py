"""
Semantic Chunker for Advanced RAG System

This module provides multiple document chunking strategies for enterprise-grade RAG:
- Fixed-size chunking (baseline)
- Sentence-based chunking
- Paragraph-based chunking
- Semantic similarity chunking
- Hybrid chunking (combines semantic + size constraints)

Author: Enterprise Risk Assessment System
Date: 2025-11-15
Week: 7 Session 1 - Advanced RAG Foundation
"""

import logging
import re
from typing import List, Dict, Any, Optional, Tuple
from langchain_core.documents import Document
import numpy as np

logger = logging.getLogger(__name__)


class SemanticChunker:
    """
    Advanced document chunker with multiple chunking strategies.

    Supports semantic, sentence-based, paragraph-based, and hybrid chunking
    to optimize document retrieval for RAG systems.
    """

    def __init__(self, default_chunk_size: int = 1000, default_overlap: int = 200):
        """
        Initialize the semantic chunker.

        Args:
            default_chunk_size: Default character count for fixed-size chunks
            default_overlap: Default character overlap between chunks
        """
        self.default_chunk_size = default_chunk_size
        self.default_overlap = default_overlap
        logger.info(
            f"SemanticChunker initialized: chunk_size={default_chunk_size}, "
            f"overlap={default_overlap}"
        )

    def chunk_by_fixed_size(
        self,
        text: str,
        chunk_size: Optional[int] = None,
        overlap: Optional[int] = None,
        metadata: Optional[Dict[str, Any]] = None
    ) -> List[Document]:
        """
        Chunk text into fixed-size pieces (baseline strategy).

        Args:
            text: Input text to chunk
            chunk_size: Characters per chunk (default: self.default_chunk_size)
            overlap: Character overlap between chunks (default: self.default_overlap)
            metadata: Optional metadata to attach to each chunk

        Returns:
            List of Document objects with chunked content

        Example:
            >>> chunker = SemanticChunker()
            >>> docs = chunker.chunk_by_fixed_size("Long text...", chunk_size=500)
            >>> len(docs)
            3
        """
        try:
            if not text or not isinstance(text, str):
                logger.warning("Empty or invalid text provided for fixed-size chunking")
                return []

            chunk_size = self.default_chunk_size if chunk_size is None else chunk_size
            overlap = self.default_overlap if overlap is None else overlap

            if chunk_size <= 0:
                logger.error(f"Invalid chunk_size: {chunk_size}")
                return []

            if overlap >= chunk_size:
                logger.warning(
                    f"Overlap ({overlap}) >= chunk_size ({chunk_size}), "
                    f"adjusting overlap to {chunk_size // 2}"
                )
                overlap = chunk_size // 2

            chunks = []
            text_length = len(text)
            start = 0
            chunk_id = 0

            while start < text_length:
                end = min(start + chunk_size, text_length)
                chunk_text = text[start:end].strip()

                if chunk_text:
                    doc_metadata = {
                        "chunk_id": chunk_id,
                        "chunk_strategy": "fixed_size",
                        "chunk_size": chunk_size,
                        "overlap": overlap,
                        "start_char": start,
                        "end_char": end,
                        **(metadata or {})
                    }

                    chunks.append(Document(
                        page_content=chunk_text,
                        metadata=doc_metadata
                    ))
                    chunk_id += 1

                start += chunk_size - overlap

                # Prevent infinite loop
                if overlap == chunk_size:
                    break

            logger.info(
                f"Fixed-size chunking completed: {len(chunks)} chunks created "
                f"from {text_length} characters"
            )
            return chunks

        except Exception as e:
            logger.error(f"Error in chunk_by_fixed_size: {e}", exc_info=True)
            return []

    def chunk_by_sentences(
        self,
        text: str,
        max_sentences: int = 10,
        metadata: Optional[Dict[str, Any]] = None
    ) -> List[Document]:
        """
        Chunk text by sentence boundaries.

        Args:
            text: Input text to chunk
            max_sentences: Maximum sentences per chunk
            metadata: Optional metadata to attach to each chunk

        Returns:
            List of Document objects with sentence-based chunks

        Example:
            >>> chunker = SemanticChunker()
            >>> docs = chunker.chunk_by_sentences("First. Second. Third.", max_sentences=2)
            >>> len(docs)
            2
        """
        try:
            if not text or not isinstance(text, str):
                logger.warning("Empty or invalid text provided for sentence chunking")
                return []

            if max_sentences <= 0:
                logger.error(f"Invalid max_sentences: {max_sentences}")
                return []

            # Split into sentences using regex (handles ., !, ?)
            # Improved regex to handle abbreviations and edge cases
            sentence_pattern = r'(?<!\w\.\w.)(?<![A-Z][a-z]\.)(?<=\.|\?|!)\s+'
            sentences = re.split(sentence_pattern, text)
            sentences = [s.strip() for s in sentences if s.strip()]

            if not sentences:
                logger.warning("No sentences found in text")
                return []

            chunks = []
            chunk_id = 0

            for i in range(0, len(sentences), max_sentences):
                chunk_sentences = sentences[i:i + max_sentences]
                chunk_text = ' '.join(chunk_sentences)

                doc_metadata = {
                    "chunk_id": chunk_id,
                    "chunk_strategy": "sentence_based",
                    "sentence_count": len(chunk_sentences),
                    "max_sentences": max_sentences,
                    **(metadata or {})
                }

                chunks.append(Document(
                    page_content=chunk_text,
                    metadata=doc_metadata
                ))
                chunk_id += 1

            logger.info(
                f"Sentence chunking completed: {len(chunks)} chunks from "
                f"{len(sentences)} sentences"
            )
            return chunks

        except Exception as e:
            logger.error(f"Error in chunk_by_sentences: {e}", exc_info=True)
            return []

    def chunk_by_paragraphs(
        self,
        text: str,
        metadata: Optional[Dict[str, Any]] = None
    ) -> List[Document]:
        """
        Chunk text by paragraph boundaries (double newlines).

        Args:
            text: Input text to chunk
            metadata: Optional metadata to attach to each chunk

        Returns:
            List of Document objects with paragraph-based chunks

        Example:
            >>> chunker = SemanticChunker()
            >>> text = "Para 1.\\n\\nPara 2.\\n\\nPara 3."
            >>> docs = chunker.chunk_by_paragraphs(text)
            >>> len(docs)
            3
        """
        try:
            if not text or not isinstance(text, str):
                logger.warning("Empty or invalid text provided for paragraph chunking")
                return []

            # Split on multiple newlines (2 or more)
            paragraphs = re.split(r'\n\s*\n+', text)
            paragraphs = [p.strip() for p in paragraphs if p.strip()]

            if not paragraphs:
                logger.warning("No paragraphs found in text")
                return []

            chunks = []
            chunk_id = 0

            for paragraph in paragraphs:
                doc_metadata = {
                    "chunk_id": chunk_id,
                    "chunk_strategy": "paragraph_based",
                    "char_count": len(paragraph),
                    **(metadata or {})
                }

                chunks.append(Document(
                    page_content=paragraph,
                    metadata=doc_metadata
                ))
                chunk_id += 1

            logger.info(
                f"Paragraph chunking completed: {len(chunks)} chunks created"
            )
            return chunks

        except Exception as e:
            logger.error(f"Error in chunk_by_paragraphs: {e}", exc_info=True)
            return []

    def chunk_by_semantic_similarity(
        self,
        text: str,
        threshold: float = 0.75,
        window_size: int = 3,
        metadata: Optional[Dict[str, Any]] = None
    ) -> List[Document]:
        """
        Chunk text based on semantic similarity between sentences.

        Splits when similarity between sentence groups drops below threshold.
        Uses simple cosine similarity with TF-IDF-like word vectors.

        Args:
            text: Input text to chunk
            threshold: Similarity threshold (0-1) for splitting
            window_size: Number of sentences to compare
            metadata: Optional metadata to attach to each chunk

        Returns:
            List of Document objects with semantic chunks

        Example:
            >>> chunker = SemanticChunker()
            >>> docs = chunker.chunk_by_semantic_similarity("Text about topic A. More about A. Now topic B.")
            >>> len(docs) >= 1
            True
        """
        try:
            if not text or not isinstance(text, str):
                logger.warning("Empty or invalid text for semantic chunking")
                return []

            if not 0 <= threshold <= 1:
                logger.error(f"Invalid threshold: {threshold}, must be 0-1")
                return []

            # Split into sentences
            sentence_pattern = r'(?<!\w\.\w.)(?<![A-Z][a-z]\.)(?<=\.|\?|!)\s+'
            sentences = re.split(sentence_pattern, text)
            sentences = [s.strip() for s in sentences if s.strip()]

            if len(sentences) <= 1:
                logger.info("Not enough sentences for semantic chunking, returning as single chunk")
                return [Document(
                    page_content=text,
                    metadata={
                        "chunk_id": 0,
                        "chunk_strategy": "semantic_similarity",
                        "sentence_count": len(sentences),
                        **(metadata or {})
                    }
                )]

            # Calculate simple semantic similarity using word overlap
            chunks = []
            current_chunk = [sentences[0]]
            chunk_id = 0

            for i in range(1, len(sentences)):
                # Get word sets for comparison
                prev_words = set(self._tokenize(sentences[i-1]))
                curr_words = set(self._tokenize(sentences[i]))

                # Calculate similarity (Jaccard coefficient as simple alternative)
                if prev_words and curr_words:
                    similarity = len(prev_words & curr_words) / len(prev_words | curr_words)
                else:
                    similarity = 0.0

                # If similarity below threshold, start new chunk
                if similarity < threshold and len(current_chunk) >= window_size:
                    chunk_text = ' '.join(current_chunk)
                    doc_metadata = {
                        "chunk_id": chunk_id,
                        "chunk_strategy": "semantic_similarity",
                        "sentence_count": len(current_chunk),
                        "threshold": threshold,
                        "last_similarity": round(similarity, 3),
                        **(metadata or {})
                    }
                    chunks.append(Document(
                        page_content=chunk_text,
                        metadata=doc_metadata
                    ))
                    current_chunk = [sentences[i]]
                    chunk_id += 1
                else:
                    current_chunk.append(sentences[i])

            # Add final chunk
            if current_chunk:
                chunk_text = ' '.join(current_chunk)
                doc_metadata = {
                    "chunk_id": chunk_id,
                    "chunk_strategy": "semantic_similarity",
                    "sentence_count": len(current_chunk),
                    "threshold": threshold,
                    **(metadata or {})
                }
                chunks.append(Document(
                    page_content=chunk_text,
                    metadata=doc_metadata
                ))

            logger.info(
                f"Semantic chunking completed: {len(chunks)} chunks from "
                f"{len(sentences)} sentences (threshold={threshold})"
            )
            return chunks

        except Exception as e:
            logger.error(f"Error in chunk_by_semantic_similarity: {e}", exc_info=True)
            return []

    def chunk_hybrid(
        self,
        text: str,
        strategy: str = 'semantic',
        max_size: int = 1500,
        min_size: int = 100,
        metadata: Optional[Dict[str, Any]] = None,
        **kwargs
    ) -> List[Document]:
        """
        Hybrid chunking strategy combining semantic/sentence/paragraph with size constraints.

        Args:
            text: Input text to chunk
            strategy: Base strategy ('semantic', 'sentence', 'paragraph')
            max_size: Maximum characters per chunk
            min_size: Minimum characters per chunk
            metadata: Optional metadata to attach to each chunk
            **kwargs: Additional arguments for base strategy

        Returns:
            List of Document objects with hybrid chunks

        Example:
            >>> chunker = SemanticChunker()
            >>> docs = chunker.chunk_hybrid("Long text...", strategy='semantic', max_size=1000)
            >>> all(len(d.page_content) <= 1000 for d in docs)
            True
        """
        try:
            if not text or not isinstance(text, str):
                logger.warning("Empty or invalid text for hybrid chunking")
                return []

            # Get base chunks using selected strategy
            if strategy == 'semantic':
                base_chunks = self.chunk_by_semantic_similarity(text, metadata=metadata, **kwargs)
            elif strategy == 'sentence':
                base_chunks = self.chunk_by_sentences(text, metadata=metadata, **kwargs)
            elif strategy == 'paragraph':
                base_chunks = self.chunk_by_paragraphs(text, metadata=metadata)
            else:
                logger.error(f"Invalid strategy: {strategy}")
                return []

            # Apply size constraints
            final_chunks = []
            chunk_id = 0

            for base_chunk in base_chunks:
                content = base_chunk.page_content

                # If chunk too large, split it
                if len(content) > max_size:
                    # Split using fixed-size with overlap
                    sub_chunks = self.chunk_by_fixed_size(
                        content,
                        chunk_size=max_size,
                        overlap=self.default_overlap
                    )
                    for sub_chunk in sub_chunks:
                        sub_chunk.metadata.update({
                            "chunk_id": chunk_id,
                            "chunk_strategy": f"hybrid_{strategy}",
                            "base_strategy": strategy,
                            "size_constrained": True,
                            "max_size": max_size,
                            **(metadata or {})
                        })
                        final_chunks.append(sub_chunk)
                        chunk_id += 1

                # If chunk too small, try to merge with previous
                elif len(content) < min_size and final_chunks:
                    last_chunk = final_chunks[-1]
                    merged_content = last_chunk.page_content + " " + content

                    # Only merge if combined size is reasonable
                    if len(merged_content) <= max_size:
                        last_chunk.page_content = merged_content
                        last_chunk.metadata["merged"] = True
                        last_chunk.metadata["chunk_count"] = last_chunk.metadata.get("chunk_count", 1) + 1
                    else:
                        # Can't merge, add as is
                        base_chunk.metadata.update({
                            "chunk_id": chunk_id,
                            "chunk_strategy": f"hybrid_{strategy}",
                            "base_strategy": strategy,
                            "below_min_size": True,
                            **(metadata or {})
                        })
                        final_chunks.append(base_chunk)
                        chunk_id += 1
                else:
                    # Size is good, add as is
                    base_chunk.metadata.update({
                        "chunk_id": chunk_id,
                        "chunk_strategy": f"hybrid_{strategy}",
                        "base_strategy": strategy,
                        **(metadata or {})
                    })
                    final_chunks.append(base_chunk)
                    chunk_id += 1

            logger.info(
                f"Hybrid chunking completed: {len(final_chunks)} chunks using "
                f"{strategy} base strategy (max_size={max_size})"
            )
            return final_chunks

        except Exception as e:
            logger.error(f"Error in chunk_hybrid: {e}", exc_info=True)
            return []

    def _tokenize(self, text: str) -> List[str]:
        """
        Simple word tokenizer for semantic similarity calculation.

        Args:
            text: Input text

        Returns:
            List of lowercase word tokens
        """
        # Remove punctuation and split on whitespace
        words = re.findall(r'\b\w+\b', text.lower())
        return words

    def chunk_document(
        self,
        document: Document,
        strategy: str = 'hybrid',
        **kwargs
    ) -> List[Document]:
        """
        Convenience method to chunk a full Document object.

        Args:
            document: Input Document to chunk
            strategy: Chunking strategy to use
            **kwargs: Additional arguments for chunking strategy

        Returns:
            List of chunked Documents with preserved metadata

        Example:
            >>> chunker = SemanticChunker()
            >>> doc = Document(page_content="Text...", metadata={"source": "file.pdf"})
            >>> chunks = chunker.chunk_document(doc, strategy='semantic')
            >>> all(c.metadata.get("source") == "file.pdf" for c in chunks)
            True
        """
        try:
            if not document or not isinstance(document, Document):
                logger.error("Invalid document provided")
                return []

            text = document.page_content
            base_metadata = document.metadata.copy() if document.metadata else {}

            strategy_map = {
                'fixed': self.chunk_by_fixed_size,
                'sentence': self.chunk_by_sentences,
                'paragraph': self.chunk_by_paragraphs,
                'semantic': self.chunk_by_semantic_similarity,
                'hybrid': self.chunk_hybrid
            }

            if strategy not in strategy_map:
                logger.error(f"Unknown strategy: {strategy}")
                return []

            chunks = strategy_map[strategy](text, metadata=base_metadata, **kwargs)

            logger.info(
                f"Document chunked: {len(chunks)} chunks created using {strategy} strategy"
            )
            return chunks

        except Exception as e:
            logger.error(f"Error in chunk_document: {e}", exc_info=True)
            return []


def main():
    """Example usage of SemanticChunker."""
    # Configure logging
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )

    # Sample text
    sample_text = """
    Artificial intelligence is transforming cybersecurity. Machine learning algorithms can detect
    anomalies in network traffic. These systems learn from historical data to identify threats.

    Risk assessment has evolved with AI capabilities. Traditional methods relied on manual analysis.
    Modern approaches use automated tools for faster evaluation. This improves response times significantly.

    Enterprise security requires multiple layers of defense. Firewalls protect network perimeters.
    Intrusion detection systems monitor internal traffic. Security teams must coordinate these tools effectively.
    """

    # Initialize chunker
    chunker = SemanticChunker(default_chunk_size=200, default_overlap=50)

    # Test each strategy
    print("\n=== Fixed-Size Chunking ===")
    fixed_chunks = chunker.chunk_by_fixed_size(sample_text, chunk_size=200)
    for i, chunk in enumerate(fixed_chunks):
        print(f"Chunk {i}: {len(chunk.page_content)} chars")

    print("\n=== Sentence-Based Chunking ===")
    sentence_chunks = chunker.chunk_by_sentences(sample_text, max_sentences=3)
    for i, chunk in enumerate(sentence_chunks):
        print(f"Chunk {i}: {chunk.metadata.get('sentence_count')} sentences")

    print("\n=== Paragraph-Based Chunking ===")
    para_chunks = chunker.chunk_by_paragraphs(sample_text)
    for i, chunk in enumerate(para_chunks):
        print(f"Chunk {i}: {len(chunk.page_content)} chars")

    print("\n=== Semantic Similarity Chunking ===")
    semantic_chunks = chunker.chunk_by_semantic_similarity(sample_text, threshold=0.3)
    for i, chunk in enumerate(semantic_chunks):
        print(f"Chunk {i}: {chunk.metadata.get('sentence_count')} sentences")

    print("\n=== Hybrid Chunking ===")
    hybrid_chunks = chunker.chunk_hybrid(sample_text, strategy='semantic', max_size=300)
    for i, chunk in enumerate(hybrid_chunks):
        print(f"Chunk {i}: {len(chunk.page_content)} chars")


if __name__ == "__main__":
    main()
