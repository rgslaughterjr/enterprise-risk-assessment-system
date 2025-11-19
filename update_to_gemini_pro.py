"""
Update all agents to use gemini-pro - the most stable and reliable model.
"""

import os
import re
from pathlib import Path

def update_model_in_file(file_path, new_model='gemini-pro'):
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
    new_model = 'gemini-pro'
    
    print(f"Updating all agents to use: {new_model}")
    print("=" * 60)
    
    fixed_count = 0
    for py_file in src_dir.glob('*_agent.py'):
        if update_model_in_file(py_file, new_model):
            print(f"✅ Updated: {py_file.name}")
            fixed_count += 1
    
    print("=" * 60)
    print(f"✅ Updated {fixed_count} agent files to use {new_model}")
    print(f"\n{new_model} is the most stable Gemini model:")
    print("  - Widely available")
    print("  - Proven reliability")
    print("  - Good free tier quotas")
    print("  - Production-ready")

if __name__ == '__main__':
    main()
