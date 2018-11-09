#!/bin/bash

set -e

make

python js_shellcode.py ps4ren.bin -o exploit/ps4hen.js
