"""
setup_loader.py
Build the helioporbit_loader C extension.

Usage:
    python setup_loader.py build_ext --inplace

After build, a file like:
    helioporbit_loader.cpython-312-x86_64-linux-gnu.so   (Linux)
    helioporbit_loader.cp312-win_amd64.pyd                (Windows)
will appear in the helioporbit/ package directory.
"""

from setuptools import setup, Extension
import sys
import os

ext = Extension(
    name="helioporbit_loader",
    sources=["helioporbit_loader.c"],
    extra_compile_args=(
        ["/O2", "/W3"]          if sys.platform == "win32"
        else ["-O2", "-Wall", "-Wextra", "-std=c99"]
    ),
    # No external dependencies — fully self-contained
)

setup(
    name="helioporbit-loader",
    version="1.0.0",
    description="Helioporbit encrypted bytecode loader (C extension)",
    ext_modules=[ext],
)
