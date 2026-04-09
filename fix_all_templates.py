"""
Run this from your project root:
    python fix_all_templates.py

Fixes all datetime[:16] slicing in Jinja templates for PostgreSQL compatibility.
Changes:  x.attr[:16]  →  (x.attr|string)[:16]
"""
import re, os, glob

templates_dir = os.path.join(os.path.dirname(__file__), 'templates')
if not os.path.isdir(templates_dir):
    print(f"ERROR: templates/ folder not found at {templates_dir}")
    print("Make sure you run this script from your project root folder.")
    exit(1)

pattern = re.compile(r'(\b\w+\.\w+(?:\.\w+)*)\[:16\]')
total_fixes = 0

for filepath in glob.glob(os.path.join(templates_dir, '*.html')):
    fname = os.path.basename(filepath)
    with open(filepath, 'r', encoding='utf-8') as f:
        content = f.read()
    
    matches = pattern.findall(content)
    if not matches:
        continue
    
    fixed = pattern.sub(r'(\1|string)[:16]', content)
    
    with open(filepath, 'w', encoding='utf-8') as f:
        f.write(fixed)
    
    count = len(matches)
    total_fixes += count
    print(f"  ✅ {fname}: {count} fixes applied")

if total_fixes == 0:
    print("  No fixes needed — all templates are already up to date.")
else:
    print(f"\nDone! {total_fixes} total fixes across all templates.")
    print("The |string filter converts datetime objects to strings before slicing.")
