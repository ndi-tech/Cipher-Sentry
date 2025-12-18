#!/usr/bin/env python3
import re
import sys

with open('main.py', 'r') as f:
    lines = f.readlines()

# Fix common issues
fixed_lines = []
for i, line in enumerate(lines, 1):
    # Fix sysv import
    if 'import sysv' in line:
        print(f"Line {i}: Fixed 'sysv' import to 'sys' and 'signal'")
        fixed_lines.append('import sys\n')
        fixed_lines.append('import signal\n')
        continue
    
    # Fix other potential import issues
    if re.match(r'^\s*import\s+[a-zA-Z_][a-zA-Z0-9_]*$', line):
        # Valid import line, keep as is
        fixed_lines.append(line)
    else:
        fixed_lines.append(line)

# Write fixed file
with open('main_final.py', 'w') as f:
    f.writelines(fixed_lines)

print("Created main_final.py with all fixes")