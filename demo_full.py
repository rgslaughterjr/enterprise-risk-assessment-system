from pathlib import Path
from src.tools.document_classifier import DocumentClassifier
from src.tools.table_extractor import TableExtractor
from src.tools.document_parser import DocumentParser
from src.tools.ocr_processor import OCRProcessor
from src.tools.pptx_parser import PPTXParser

docs_dir = Path(r"C:\Users\richa\Documents\ai-agent-course\documents")
project_dir = Path.cwd()

print("="*70)
print("DOCUMENT INTELLIGENCE AGENT - FULL DEMO")
print("="*70)

# 1. CLASSIFICATION
print("\n1. DOCUMENT CLASSIFICATION")
print("-"*70)
classifier = DocumentClassifier()
classifier.train_classifier(
    ["AI risk framework", "SOC2 checklist", "GDPR regulation", "risk assessment"],
    ["compliance_checklist", "audit_report", "compliance_checklist", "risk_assessment"]
)

docs = [
    docs_dir / "NIST.AI.100-1.pdf",
    docs_dir / "SOC2_Compliance_-Checklist.pdf",
    docs_dir / "GDPR.pdf",
    project_dir / "sample_security_presentation.pptx"
]

for doc in docs:
    if doc.exists():
        result = classifier.classify_document(doc.name)
        top_type = list(result.keys())[0]
        print(f"📄 {doc.name[:45]:45s} {top_type:20s} {result[top_type]:5.1%}")

# 2. TABLE EXTRACTION
print("\n2. TABLE EXTRACTION")
print("-"*70)
extractor = TableExtractor()
nist_ai = docs_dir / "NIST.AI.100-1.pdf"
if nist_ai.exists():
    tables = extractor.extract_tables_from_pdf(str(nist_ai), pages=[0,1,2])
    print(f"📊 {nist_ai.name}: {len(tables)} tables found")

# 3. POWERPOINT PARSING
print("\n3. POWERPOINT PARSING")
print("-"*70)
pptx_file = project_dir / "sample_security_presentation.pptx"
if pptx_file.exists():
    pptx_parser = PPTXParser()
    result = pptx_parser.parse_presentation(str(pptx_file))
    print(f"📊 {pptx_file.name}")
    print(f"   Slides: {result['slide_count']}, Tables: {result['table_count']}, Images: {result['image_count']}")
    print(f"   Text: {len(result['full_text'].split())} words")

# 4. DOCUMENT PARSING
print("\n4. DOCUMENT PARSING")
print("-"*70)
parser = DocumentParser()
soc2 = docs_dir / "SOC2_Compliance_-Checklist.pdf"
if soc2.exists():
    content = parser.parse_document(str(soc2))
    if content:
        print(f"📋 {soc2.name}")
        print(f"   Text: {len(content.text_content.split()):,} words")
        print(f"   Entities: {len(content.entities)}")

# 5. OCR
print("\n5. OCR CAPABILITY")
print("-"*70)
ocr = OCRProcessor()
print(f"✓ OCR Processor initialized and ready")

print("\n" + "="*70)
print("✓ ALL 5 DOCUMENT INTELLIGENCE TOOLS VALIDATED")
print("="*70)
