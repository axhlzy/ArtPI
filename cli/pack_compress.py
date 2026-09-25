#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
pack_compress.py - Compress payload binaries using standard library LZMA/XZ
for embedding into artpi-cli.
"""
import sys
import lzma
import os

def compress_file(src_path, dst_path):
    with open(src_path, 'rb') as f_in:
        raw_data = f_in.read()
    
    # Use preset 6 with CRC32 check (universal compatibility with xz-embedded)
    compressed = lzma.compress(raw_data, check=lzma.CHECK_CRC32, preset=6)
    with open(dst_path, 'wb') as f_out:
        f_out.write(compressed)
    
    ratio = (len(compressed) * 100.0 / len(raw_data)) if raw_data else 0
    print(f"[pack_compress] {os.path.basename(src_path)}: {len(raw_data):,} -> {len(compressed):,} bytes ({ratio:.1f}%)")

if __name__ == '__main__':
    if len(sys.argv) < 3:
        print("Usage: pack_compress.py <src> <dst>")
        sys.exit(1)
    compress_file(sys.argv[1], sys.argv[2])
