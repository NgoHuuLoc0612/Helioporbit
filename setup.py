from setuptools import setup, find_packages

setup(
    name="helioporbit",
    version="1.0.0",
    description="Python Obfuscator & Deobfuscator",
    author="Helioporbit",
    license="MIT",
    python_requires=">=3.9",
    packages=find_packages(),
    install_requires=[],
    extras_require={
        "fast": ["pycryptodome"],
    },
    entry_points={
        "console_scripts": [
            "helioporbit=helioporbit.cli:main",
        ],
    },
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
        "Topic :: Security",
        "Topic :: Software Development :: Code Generators",
    ],
)
