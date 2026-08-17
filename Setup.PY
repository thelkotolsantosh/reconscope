from pathlib import Path

from setuptools import find_packages, setup

long_description = (Path(__file__).parent / "README.md").read_text(encoding="utf-8")

setup(
    name="reconscope",
    version="1.0.0",
    description="Website reconnaissance & security profiling CLI",
    long_description=long_description,
    long_description_content_type="text/markdown",
    author="Your Name",
    license="MIT",
    packages=find_packages(exclude=["tests", "tests.*"]),
    install_requires=[
        "requests>=2.31.0",
        "dnspython>=2.6.0",
        "python-whois>=0.9.4",
        "rich>=13.7.0",
    ],
    python_requires=">=3.9",
    entry_points={
        "console_scripts": [
            "reconscope=reconscope.cli:main",
        ],
    },
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
        "Topic :: Security",
        "Intended Audience :: Information Technology",
    ],
)
