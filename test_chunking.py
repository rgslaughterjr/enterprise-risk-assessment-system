from src.tools.semantic_chunker import SemanticChunker

# Sample compliance text (realistic for your use case)
text = '''
Security Policy Requirements

Section 1: Access Control
All systems must implement role-based access control (RBAC). User permissions should follow the principle of least privilege. Access reviews are required quarterly to ensure compliance.

Section 2: Monitoring and Logging
Comprehensive audit logging must be implemented across all systems. Logs must be retained for a minimum of 90 days. Anomaly detection systems should be enabled to identify suspicious activities.

Section 3: Risk Assessment
Risk assessments are required on a quarterly basis. All high-risk findings must be remediated within 30 days. Assessment results must be presented to senior management for review and approval.

Section 4: Incident Response
An incident response plan must be documented and tested annually. The plan should include clear roles, responsibilities, and escalation procedures. Post-incident reviews are mandatory.
'''

chunker = SemanticChunker(default_chunk_size=200, default_overlap=50)

print("=" * 60)
print("ORIGINAL TEXT LENGTH:", len(text), "characters")
print("=" * 60)

# Test 1: Fixed-size chunking
print("\n1. FIXED-SIZE CHUNKING (200 chars, 50 overlap)")
print("-" * 60)
fixed = chunker.chunk_by_fixed_size(text, chunk_size=200, overlap=50)
print(f"Created {len(fixed)} chunks")
for i, chunk in enumerate(fixed[:3]):  # Show first 3
    print(f"\nChunk {i+1} ({len(chunk.page_content)} chars):")
    print(chunk.page_content[:100] + "...")

# Test 2: Sentence-based chunking
print("\n\n2. SENTENCE-BASED CHUNKING (max 3 sentences per chunk)")
print("-" * 60)
sentences = chunker.chunk_by_sentences(text, max_sentences=3)
print(f"Created {len(sentences)} chunks")
for i, chunk in enumerate(sentences[:2]):  # Show first 2
    print(f"\nChunk {i+1}:")
    print(chunk.page_content)

# Test 3: Paragraph-based chunking
print("\n\n3. PARAGRAPH-BASED CHUNKING")
print("-" * 60)
paragraphs = chunker.chunk_by_paragraphs(text)
print(f"Created {len(paragraphs)} chunks")
for i, chunk in enumerate(paragraphs[:2]):  # Show first 2
    print(f"\nChunk {i+1} (Section {i+1}):")
    print(chunk.page_content[:150] + "...")

# Test 4: Semantic similarity chunking
print("\n\n4. SEMANTIC SIMILARITY CHUNKING (threshold=0.3)")
print("-" * 60)
semantic = chunker.chunk_by_semantic_similarity(text, threshold=0.3)
print(f"Created {len(semantic)} chunks")
for i, chunk in enumerate(semantic[:2]):  # Show first 2
    print(f"\nChunk {i+1}:")
    print(chunk.page_content[:150] + "...")

# Test 5: Hybrid chunking
print("\n\n5. HYBRID CHUNKING (semantic + 300 char max)")
print("-" * 60)
hybrid = chunker.chunk_hybrid(text, strategy='semantic', max_size=300)
print(f"Created {len(hybrid)} chunks")
for i, chunk in enumerate(hybrid[:2]):  # Show first 2
    print(f"\nChunk {i+1} ({len(chunk.page_content)} chars):")
    print(chunk.page_content[:150] + "...")

# Compare strategies
print("\n\n" + "=" * 60)
print("SUMMARY COMPARISON")
print("=" * 60)
print(f"Fixed-size:   {len(fixed):2d} chunks (mechanical splitting)")
print(f"Sentences:    {len(sentences):2d} chunks (respects sentence boundaries)")
print(f"Paragraphs:   {len(paragraphs):2d} chunks (respects document structure)")
print(f"Semantic:     {len(semantic):2d} chunks (groups similar content)")
print(f"Hybrid:       {len(hybrid):2d} chunks (semantic + size constraints)")
print("\nBest for compliance docs: Paragraphs or Semantic")
print("Best for general text: Hybrid (balances coherence + size)")
