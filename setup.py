from setuptools import setup, find_packages

setup(
    name="ads_scanner",
    version="1.0.0",
    author="Ayesha",
    description="A command-line tool to detect, view, delete, and restore Alternate Data Streams (ADS) on Windows.",
    py_modules=["scanner"],
    packages=find_packages(),
    install_requires=[],
    entry_points={
        'console_scripts': [
            'ads_scanner = scanner:main',
        ],
    },
)
