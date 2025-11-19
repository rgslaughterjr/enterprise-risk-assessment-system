"""
Fix all relative imports in the src directory to use absolute imports.
This script will update all Python files to use absolute imports instead of relative imports.
"""

import os
import re
from pathlib import Path

def fix_imports_in_file(file_path):
    """Fix relative imports in a single file."""
    with open(file_path, 'r', encoding='utf-8') as f:
        content = f.read()
    
    original_content = content
    
    # Add sys.path setup if not present
    if 'import sys' not in content and 'from ..' in content:
        # Find the first import statement
        import_match = re.search(r'^(import |from )', content, re.MULTILINE)
        if import_match:
            insert_pos = import_match.start()
            path_setup = """import sys
from pathlib import Path

# Ensure src is in path for absolute imports
_src_path = str(Path(__file__).parent.parent)
if _src_path not in sys.path:
    sys.path.insert(0, _src_path)

"""
            content = content[:insert_pos] + path_setup + content[insert_pos:]
    
    # Replace relative imports with absolute imports
    # Pattern: from ..module import something -> from module import something
    content = re.sub(r'from \.\.([a-zA-Z_][a-zA-Z0-9_]*)', r'from \1', content)
    
    # Only write if changed
    if content != original_content:
        with open(file_path, 'w', encoding='utf-8') as f:
            f.write(content)
        return True
    return False

def main():
    src_dir = Path(__file__).parent / 'src'
    
    print("Fixing relative imports in all Python files...")
    print("=" * 60)
    
    fixed_count = 0
    for py_file in src_dir.rglob('*.py'):
        if '__pycache__' in str(py_file):
            continue
        
        if fix_imports_in_file(py_file):
            print(f"✅ Fixed: {py_file.relative_to(src_dir)}")
            fixed_count += 1
    
    print("=" * 60)
    print(f"✅ Fixed {fixed_count} files")

if __name__ == '__main__':
    main()
