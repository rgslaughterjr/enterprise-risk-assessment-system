"""
Update all agents to use gemini-1.5-flash instead of experimental models.
This model has better quota limits and is production-ready.
"""

import os
import re
from pathlib import Path

def update_model_in_file(file_path, old_model, new_model):
    """Update model name in a file."""
    with open(file_path, 'r', encoding='utf-8') as f:
        content = f.read()
    
    original_content = content
    
    # Replace model name in default parameter
    content = re.sub(
        rf'model:\s*str\s*=\s*["\']({old_model})["\']',
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
    
    old_models = ['gemini-2.0-flash-exp', 'gemini-1.5-pro', 'gemini-2.0-flash']
    new_model = 'gemini-1.5-flash'
    
    print(f"Updating all agents to use: {new_model}")
    print("=" * 60)
    
    fixed_count = 0
    for py_file in src_dir.glob('*_agent.py'):
        for old_model in old_models:
            if update_model_in_file(py_file, old_model, new_model):
                print(f"✅ Updated: {py_file.name}")
                fixed_count += 1
                break
    
    print("=" * 60)
    print(f"✅ Updated {fixed_count} agent files to use {new_model}")
    print(f"\n{new_model} benefits:")
    print("  - Production-ready and stable")
    print("  - Better free tier quotas")
    print("  - Fast response times")
    print("  - Reliable for all use cases")

if __name__ == '__main__':
    main()
