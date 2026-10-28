from setuptools import setup, find_packages

setup(
    name="cyber-engine-sdk",
    version="0.1.0",
    description="Python SDK for CYBER ENGINE adaptive infrastructure security platform",
    author="CYBER ENGINE Team",
    packages=find_packages(),
    install_requires=[
        "httpx>=0.25.0",
    ],
    python_requires=">=3.10",
)
