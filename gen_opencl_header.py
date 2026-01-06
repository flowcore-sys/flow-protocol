#!/usr/bin/env python3
"""Generate embedded OpenCL kernel header from keccak256.cl"""

import os

script_dir = os.path.dirname(os.path.abspath(__file__))
src_file = os.path.join(script_dir, 'src', 'miner', 'keccak256.cl')
dst_file = os.path.join(script_dir, 'src', 'miner', 'keccak256_cl_embedded.h')

with open(src_file, 'r') as f:
    content = f.read()

# Escape for C string literal
escaped = content.replace('\\', '\\\\')
escaped = escaped.replace('"', '\\"')
escaped = escaped.replace('\n', '\\n"\n"')

with open(dst_file, 'w') as f:
    f.write('/* Auto-generated from keccak256.cl - DO NOT EDIT */\n')
    f.write('"' + escaped + '"\n')

print(f'Generated {dst_file}')
