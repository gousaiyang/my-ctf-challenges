#!/bin/bash
set -ex
cd "$(dirname "$(realpath "$0")")"
gcc readflag.c -o readflag
cd audit_sandbox
python3.8 setup.py build
cp build/lib*/audit_sandbox* ../src/audit_sandbox.so
cd ../src
strip -s audit_sandbox.so
chmod +x pyaucalc.py
