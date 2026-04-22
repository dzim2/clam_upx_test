#!/usr/bin/env python3

import argparse
import os
import subprocess
from pathlib import Path
import sys

xor_key = b'\
bhcftqarohcdiayfohalohkgmoefxrrg\
fnczssgybajvkzjaahpfrlqsratkhhfv\
pxytculmwgmtyzujlbjlgrhtwxhzpjaz\
libbwepffyjyfkjwzyofgpopoueurinp\
dujkphxwhnaxfkaiwrpzdqsnwughtejr\
'

def xor_file(in_file: Path, out_file: Path):
    data = in_file.read_bytes()
    out = bytearray()

    i = 0
    while i < len(data):
        for j in range(len(xor_key)):
            if i + j == len(data):
                break
            out.append(data[i + j] ^ xor_key[j])
        i += len(xor_key)

    with out_file.open("wb") as f:
        f.write(out)

    print(f"[XOR] {out_file}")


def run_upx(in_file: Path, out_file: Path):
    try:
        subprocess.run(
            ["upx", "-o", str(out_file), str(in_file)],
            check=True
        )
        print(f"[UPX] {out_file}")
        return True
    except Exception as e:
        print(f"[UPX] Failed: {in_file} ({e})")
        return False


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--dir", required=True)
    parser.add_argument("--upx", action="store_true")
    args = parser.parse_args()

    d = Path(args.dir)

    if not d.is_dir():
        print(f"Error: {d} is not a directory")
        sys.exit(1)

    for f in d.iterdir():
        if not f.is_file():
            continue

        name = f.name.lower()

        # skip already processed
        if f.suffix == ".xor":
            continue
        if "upx" in name:
            continue

        try:
            if args.upx:
                upx_file = f.with_name(f.name + ".upx")

                if upx_file.exists():
                    os.remove(upx_file)

                if not run_upx(f, upx_file):
                    continue

                xor_out = upx_file.with_name(upx_file.name + ".xor")

                if xor_out.exists():
                    os.remove(xor_out)

                xor_file(upx_file, xor_out)

            else:
                xor_out = f.with_name(f.name + ".xor")

                if xor_out.exists():
                    os.remove(xor_out)

                xor_file(f, xor_out)

        except Exception as e:
            print(f"[ERROR] {f}: {e}")

    print("Done.")


if __name__ == "__main__":
    main()