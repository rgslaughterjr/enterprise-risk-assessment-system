"""
Tool API Discovery and Validation Script
"""
import sys
from pathlib import Path
import importlib

def check_tool(module_path, class_name):
    """Check tool API and dependencies."""
    print(f"\n{'='*60}")
    print(f"Checking: {class_name}")
    print('='*60)
    
    try:
        module = importlib.import_module(module_path)
        tool_class = getattr(module, class_name)
        instance = tool_class()
        
        # Get public methods
        methods = [m for m in dir(instance) if not m.startswith('_')]
        print(f"✓ Import successful")
        print(f"✓ {len(methods)} public methods/attributes")
        print(f"\nMethods:")
        for method in methods:
            attr = getattr(instance, method)
            if callable(attr):
                print(f"  - {method}()")
            else:
                print(f"  - {method} (attribute)")
        
        return True, instance, methods
        
    except Exception as e:
        print(f"✗ Error: {e}")
        return False, None, []

# Check all tools
tools = [
    ('src.tools.document_classifier', 'DocumentClassifier'),
    ('src.tools.ocr_processor', 'OCRProcessor'),
    ('src.tools.table_extractor', 'TableExtractor'),
    ('src.tools.pptx_parser', 'PPTXParser'),
    ('src.tools.document_parser', 'DocumentParser'),
]

results = {}
for module_path, class_name in tools:
    success, instance, methods = check_tool(module_path, class_name)
    results[class_name] = {
        'success': success,
        'instance': instance,
        'methods': methods
    }

# Summary
print(f"\n{'='*60}")
print("SUMMARY")
print('='*60)
for name, data in results.items():
    status = '✓' if data['success'] else '✗'
    print(f"{status} {name}")

if all(r['success'] for r in results.values()):
    print("\n✓ ALL TOOLS READY FOR DEMO")
else:
    print("\n✗ Some tools failed")
