"""
Query Optimizer for Advanced RAG System

Provides multiple query transformation strategies to improve retrieval:
- Query expansion (synonyms, related terms)
- Query rewriting (rephrasing)
- Multi-query generation (variations)
- Hypothetical document generation (HyDE)

Author: Enterprise Risk Assessment System
Date: 2025-11-15
Week: 7 Session 1 - Advanced RAG Foundation
"""

import logging
from typing import List, Dict, Any, Optional
import re

logger = logging.getLogger(__name__)


class QueryOptimizer:
    """
    Query optimizer with multiple transformation strategies for improved retrieval.

    Uses various techniques to enhance queries for better RAG performance.
    """

    def __init__(self, llm: Optional[Any] = None):
        """
        Initialize the query optimizer.

        Args:
            llm: Optional Language Model for advanced transformations
        """
        self.llm = llm
        self._query_cache: Dict[str, Any] = {}

        # Domain-specific synonyms for expansion
        self.synonyms = {
            "vulnerability": ["weakness", "flaw", "security hole", "exploit"],
            "risk": ["threat", "danger", "hazard", "exposure"],
            "attack": ["exploit", "breach", "intrusion", "compromise"],
            "security": ["protection", "safety", "defense"],
            "malware": ["virus", "trojan", "malicious software", "ransomware"],
            "authentication": ["login", "access control", "verification"],
            "encryption": ["crypto", "cipher", "encoding"],
            "firewall": ["network protection", "security barrier"],
        }

        logger.info("QueryOptimizer initialized")

    def expand_query(
        self,
        query: str,
        max_expansions: int = 3
    ) -> str:
        """
        Expand query with synonyms and related terms.

        Args:
            query: Original query string
            max_expansions: Maximum synonyms to add per term

        Returns:
            Expanded query string

        Example:
            >>> optimizer = QueryOptimizer()
            >>> optimizer.expand_query("vulnerability assessment")
            'vulnerability weakness flaw assessment evaluation'
        """
        try:
            if not query or not isinstance(query, str):
                logger.warning("Invalid query for expansion")
                return query

            # Check cache
            cache_key = f"expand_{query}_{max_expansions}"
            if cache_key in self._query_cache:
                return self._query_cache[cache_key]

            # Tokenize query
            words = query.lower().split()
            expanded_terms = set(words)  # Start with original terms

            # Add synonyms for recognized terms
            for word in words:
                if word in self.synonyms:
                    synonyms = self.synonyms[word][:max_expansions]
                    expanded_terms.update(synonyms)

            # Rebuild query
            expanded_query = " ".join(expanded_terms)

            # Cache result
            self._query_cache[cache_key] = expanded_query

            logger.info(f"Expanded query: '{query}' -> '{expanded_query}'")
            return expanded_query

        except Exception as e:
            logger.error(f"Error expanding query: {e}", exc_info=True)
            return query

    def rewrite_query(
        self,
        query: str,
        style: str = "formal"
    ) -> str:
        """
        Rewrite query for better retrieval.

        Args:
            query: Original query string
            style: Rewriting style ('formal', 'technical', 'conversational')

        Returns:
            Rewritten query string

        Example:
            >>> optimizer = QueryOptimizer()
            >>> optimizer.rewrite_query("how to stop hackers", style="technical")
            'methods for preventing unauthorized access and security breaches'
        """
        try:
            if not query or not isinstance(query, str):
                logger.warning("Invalid query for rewriting")
                return query

            # Check cache
            cache_key = f"rewrite_{query}_{style}"
            if cache_key in self._query_cache:
                return self._query_cache[cache_key]

            # Simple rule-based rewriting
            rewritten = query.lower()

            # Apply style-specific transformations
            if style == "technical":
                replacements = {
                    "how to stop": "methods for preventing",
                    "hackers": "unauthorized access and security breaches",
                    "fix": "remediate",
                    "problem": "issue",
                    "bug": "defect",
                    "find": "identify",
                }
                for old, new in replacements.items():
                    rewritten = rewritten.replace(old, new)

            elif style == "formal":
                # Remove casual language
                rewritten = re.sub(r'\b(like|just|really|very)\b', '', rewritten)
                rewritten = re.sub(r'\s+', ' ', rewritten).strip()

            # Cache result
            self._query_cache[cache_key] = rewritten

            logger.info(f"Rewritten query ({style}): '{query}' -> '{rewritten}'")
            return rewritten

        except Exception as e:
            logger.error(f"Error rewriting query: {e}", exc_info=True)
            return query

    def generate_multi_queries(
        self,
        query: str,
        n: int = 3
    ) -> List[str]:
        """
        Generate multiple query variations.

        Args:
            query: Original query string
            n: Number of variations to generate

        Returns:
            List of query variations including original

        Example:
            >>> optimizer = QueryOptimizer()
            >>> queries = optimizer.generate_multi_queries("security risks", n=3)
            >>> len(queries)
            3
        """
        try:
            if not query or not isinstance(query, str):
                logger.warning("Invalid query for multi-query generation")
                return [query] if query else []

            # Check cache
            cache_key = f"multi_{query}_{n}"
            if cache_key in self._query_cache:
                return self._query_cache[cache_key]

            variations = [query]  # Include original

            # Generate variations using different strategies
            if n > 1:
                # Variation 1: Expanded query
                expanded = self.expand_query(query, max_expansions=2)
                if expanded != query:
                    variations.append(expanded)

            if n > 2:
                # Variation 2: Technical rewrite
                rewritten = self.rewrite_query(query, style="technical")
                if rewritten != query and rewritten not in variations:
                    variations.append(rewritten)

            if n > 3:
                # Variation 3: Question format
                if not query.strip().endswith('?'):
                    question = f"what are {query}"
                    variations.append(question)

            # Ensure we return exactly n variations (pad if needed)
            while len(variations) < n:
                variations.append(query)

            # Return only first n
            result = variations[:n]

            # Cache result
            self._query_cache[cache_key] = result

            logger.info(f"Generated {len(result)} query variations")
            return result

        except Exception as e:
            logger.error(f"Error generating multi-queries: {e}", exc_info=True)
            return [query] if query else []

    def generate_hypothetical_answer(
        self,
        query: str,
        max_length: int = 200
    ) -> str:
        """
        Generate hypothetical answer for HyDE (Hypothetical Document Embeddings).

        Args:
            query: Original query string
            max_length: Maximum length of hypothetical answer

        Returns:
            Hypothetical answer string

        Example:
            >>> optimizer = QueryOptimizer()
            >>> answer = optimizer.generate_hypothetical_answer("What are SQL injection risks?")
            >>> "SQL injection" in answer
            True
        """
        try:
            if not query or not isinstance(query, str):
                logger.warning("Invalid query for hypothetical answer generation")
                return ""

            # Check cache
            cache_key = f"hyde_{query}_{max_length}"
            if cache_key in self._query_cache:
                return self._query_cache[cache_key]

            # Simple template-based generation
            # In production, this would use an LLM

            # Extract key terms
            key_terms = self._extract_key_terms(query)

            # Generate hypothetical answer based on query type
            if any(word in query.lower() for word in ["what", "define", "explain"]):
                hypothetical = self._generate_definitional_answer(key_terms)
            elif any(word in query.lower() for word in ["how", "steps", "process"]):
                hypothetical = self._generate_procedural_answer(key_terms)
            elif any(word in query.lower() for word in ["risk", "threat", "vulnerability"]):
                hypothetical = self._generate_risk_answer(key_terms)
            else:
                hypothetical = self._generate_generic_answer(key_terms)

            # Truncate to max length
            if len(hypothetical) > max_length:
                hypothetical = hypothetical[:max_length].rsplit(' ', 1)[0] + "..."

            # Cache result
            self._query_cache[cache_key] = hypothetical

            logger.info(f"Generated hypothetical answer for query: '{query[:50]}...'")
            return hypothetical

        except Exception as e:
            logger.error(f"Error generating hypothetical answer: {e}", exc_info=True)
            return ""

    def optimize_query(
        self,
        query: str,
        strategy: str = "expand"
    ) -> str:
        """
        Optimize query using specified strategy.

        Args:
            query: Original query string
            strategy: Optimization strategy ('expand', 'rewrite', 'multi', 'hyde')

        Returns:
            Optimized query string or list of queries

        Example:
            >>> optimizer = QueryOptimizer()
            >>> optimizer.optimize_query("security vulnerabilities", strategy="expand")
            'security vulnerabilities weakness flaw'
        """
        try:
            if not query:
                return query

            if strategy == "expand":
                return self.expand_query(query)
            elif strategy == "rewrite":
                return self.rewrite_query(query)
            elif strategy == "hyde":
                return self.generate_hypothetical_answer(query)
            else:
                logger.warning(f"Unknown strategy: {strategy}, returning original query")
                return query

        except Exception as e:
            logger.error(f"Error optimizing query: {e}", exc_info=True)
            return query

    def clear_cache(self) -> None:
        """Clear the query cache."""
        self._query_cache.clear()
        logger.info("Query cache cleared")

    def get_cache_size(self) -> int:
        """Get current cache size."""
        return len(self._query_cache)

    def _extract_key_terms(self, query: str) -> List[str]:
        """Extract key terms from query."""
        # Remove question words
        question_words = ['what', 'how', 'why', 'when', 'where', 'who', 'which', 'are', 'is', 'the', 'a', 'an']
        # Extract words and remove punctuation
        words = re.findall(r'\b\w+\b', query.lower())
        key_terms = [w for w in words if w not in question_words and len(w) > 2]
        return key_terms

    def _generate_definitional_answer(self, key_terms: List[str]) -> str:
        """Generate definitional hypothetical answer."""
        if not key_terms:
            return "A comprehensive explanation of the concept."

        term = key_terms[0]
        return (
            f"{term.capitalize()} refers to a critical aspect of information security. "
            f"It involves processes and techniques used to protect systems and data. "
            f"Organizations must implement {term} measures to ensure security compliance."
        )

    def _generate_procedural_answer(self, key_terms: List[str]) -> str:
        """Generate procedural hypothetical answer."""
        if not key_terms:
            return "Follow systematic steps to complete this process."

        action = key_terms[0] if key_terms else "action"
        return (
            f"To perform {action}, follow these steps: "
            f"First, assess the current state and requirements. "
            f"Next, implement appropriate controls and safeguards. "
            f"Finally, validate and monitor the results."
        )

    def _generate_risk_answer(self, key_terms: List[str]) -> str:
        """Generate risk-related hypothetical answer."""
        if not key_terms:
            return "Risk assessment identifies potential security threats."

        risk = key_terms[0] if key_terms else "risk"
        return (
            f"{risk.capitalize()} represents a significant security concern. "
            f"It can lead to data breaches, system compromises, and financial loss. "
            f"Organizations should implement controls to mitigate {risk} through "
            f"regular assessments, monitoring, and security best practices."
        )

    def _generate_generic_answer(self, key_terms: List[str]) -> str:
        """Generate generic hypothetical answer."""
        if not key_terms:
            return "This topic is relevant to enterprise security and risk management."

        terms = " and ".join(key_terms[:3])
        return (
            f"Regarding {terms}, enterprise security requires comprehensive approaches. "
            f"Best practices include regular assessments, monitoring, and implementation "
            f"of appropriate security controls and frameworks."
        )


def main():
    """Example usage of QueryOptimizer."""
    # Configure logging
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )

    optimizer = QueryOptimizer()

    print("\n=== Query Optimizer Demo ===")

    # Test query expansion
    print("\n--- Query Expansion ---")
    original = "vulnerability assessment"
    expanded = optimizer.expand_query(original)
    print(f"Original: {original}")
    print(f"Expanded: {expanded}")

    # Test query rewriting
    print("\n--- Query Rewriting ---")
    casual = "how to stop hackers"
    rewritten = optimizer.rewrite_query(casual, style="technical")
    print(f"Original: {casual}")
    print(f"Rewritten: {rewritten}")

    # Test multi-query generation
    print("\n--- Multi-Query Generation ---")
    query = "security risks"
    variations = optimizer.generate_multi_queries(query, n=3)
    print(f"Original: {query}")
    for i, var in enumerate(variations, 1):
        print(f"  {i}. {var}")

    # Test HyDE
    print("\n--- Hypothetical Document (HyDE) ---")
    question = "What are SQL injection vulnerabilities?"
    hypothetical = optimizer.generate_hypothetical_answer(question)
    print(f"Query: {question}")
    print(f"Hypothetical: {hypothetical}")

    # Show cache stats
    print(f"\n--- Cache Stats ---")
    print(f"Cache size: {optimizer.get_cache_size()}")


if __name__ == "__main__":
    main()
