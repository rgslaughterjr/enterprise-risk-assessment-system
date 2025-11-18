import sys
from pathlib import Path
from src.tools.document_classifier import DocumentClassifier
from src.tools.table_extractor import TableExtractor
from src.tools.document_parser import DocumentParser

# Document paths
docs_dir = Path(r"C:\Users\richa\Documents\ai-agent-course\documents")
nist_ai = docs_dir / "NIST.AI.100-1.pdf"
soc2 = docs_dir / "SOC2_Compliance_-Checklist.pdf"
gdpr = docs_dir / "GDPR.pdf"
fair = docs_dir / "FAIR Institute -- Integrating FAIR Models for Cyber Risk Management (December 2024).pdf"

print("=== Document Intelligence Agent Demo ===\n")

# 1. Document Classifier
print("1. DOCUMENT CLASSIFICATION")
print("-" * 50)
classifier = DocumentClassifier()

# Train on sample text
training_docs = [
    "AI risk management framework guidance and controls",
    "Security control checklist compliance requirements",
    "Data protection regulation GDPR compliance",
    "Risk assessment methodology and scoring"
]
training_labels = [
    "compliance_checklist",
    "audit_report", 
    "compliance_checklist",
    "risk_assessment"
]
classifier.train_classifier(training_docs, training_labels)

# Classify documents
for doc in [nist_ai, soc2, gdpr, fair]:
    if doc.exists():
        result = classifier.classify_document(doc.name)
        if result:
            top_type = list(result.keys())[0]
            confidence = result[top_type]
            print(f"📄 {doc.name[:50]:50s} -> {top_type:20s} ({confidence:.1%})")
print()

# 2. Table Extraction
print("2. TABLE EXTRACTION FROM PDFs")
print("-" * 50)
extractor = TableExtractor()

if nist_ai.exists():
    print(f"📊 Extracting tables from {nist_ai.name}...")
    tables = extractor.extract_tables(str(nist_ai), max_pages=5)
    print(f"   Found {len(tables)} tables in first 5 pages")
    if tables:
        print(f"   First table: {tables[0]['rows']} rows x {tables[0]['cols']} cols")
        print(f"   Quality score: {tables[0]['quality_score']:.2f}")
print()

# 3. Enhanced Document Parser
print("3. DOCUMENT PARSER WITH INTELLIGENCE")
print("-" * 50)
parser = DocumentParser()

if soc2.exists():
    print(f"📋 Parsing {soc2.name}...")
    content = parser.parse_document(str(soc2))
    print(f"   Extracted {len(content['text'].split())} words")
    print(f"   Has tables: {content.get('has_tables', False)}")

print("\n=== Demo Complete ===")
