"""
Update all agents to use gemini-2.0-flash - the model available with the new API key.
"""

import os
import re
from pathlib import Path

def update_model_in_file(file_path, new_model='gemini-2.0-flash'):
    """Update model name in a file."""
    with open(file_path, 'r', encoding='utf-8') as f:
        content = f.read()
    
    original_content = content
    
    # Replace any model name in default parameter
    content = re.sub(
        r'model:\s*str\s*=\s*["\'][^"\']+["\']',
        f'model: str = "{new_model}"',
        content
    )
    
    # Only write if changed
    if content != original_content:
        with open(file_path, 'w', encoding='utf-8') as f:
            f.write(content)
        return True
    return False

def main():
    src_dir = Path(__file__).parent / 'src' / 'agents'
    new_model = 'gemini-2.0-flash'
    
    print(f"Updating all agents to use: {new_model}")
    print("=" * 60)
    
    fixed_count = 0
    for py_file in src_dir.glob('*_agent.py'):
        if update_model_in_file(py_file, new_model):
            print(f"✅ Updated: {py_file.name}")
            fixed_count += 1
    
    print("=" * 60)
    print(f"✅ Updated {fixed_count} agent files to use {new_model}")

if __name__ == '__main__':
    main()
