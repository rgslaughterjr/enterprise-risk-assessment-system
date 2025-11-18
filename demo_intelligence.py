from src.tools.document_classifier import DocumentClassifier
from src.tools.ocr_processor import OCRProcessor
from src.tools.table_extractor import TableExtractor
from pathlib import Path

# Initialize tools
classifier = DocumentClassifier()
ocr = OCRProcessor()
table_extractor = TableExtractor()

print("=== Document Intelligence Demo ===\n")

# Train classifier with sample documents
print("1. Training document classifier...")
training_docs = [
    ("This is a security policy about data encryption", "security_policy"),
    ("Risk assessment for cloud infrastructure", "risk_assessment"),
    ("Incident report: unauthorized access detected", "incident_report"),
]
classifier.train(training_docs)
print(f"   Trained on {len(training_docs)} sample documents\n")

# Classify a new document
print("2. Classifying document...")
test_doc = "Annual audit findings for compliance controls"
category, confidence = classifier.classify(test_doc)
print(f"   Category: {category}")
print(f"   Confidence: {confidence:.2%}\n")

# Show available categories
print("3. Available document categories:")
for cat in classifier.categories:
    print(f"   - {cat}")

print("\n=== Demo Complete ===")
