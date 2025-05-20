from configparser import ConfigParser
from io import open
from pathlib import Path

from setuptools import setup

from zappa import __version__

with open("README.md", encoding="utf-8") as readme_file:
    long_description = readme_file.read()

pipfile = ConfigParser()
pipfile.read(Path(__file__).parent.resolve() / "Pipfile")
required = [
    "{}{}".format(name, version.strip('"')) if version != '"*"' else name for name, version in pipfile["packages"].items()
]

setup(
    name="zappa",
    version=__version__,
    packages=["zappa"],
    install_requires=required,
    python_requires=">=3.9",
    include_package_data=True,
    license="MIT License",
    description="Server-less Python Web Services for AWS Lambda and API Gateway",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/zappa/Zappa",
    author="Rich Jones",
    author_email="rich@openwatch.net",
    entry_points={
        "console_scripts": [
            "zappa=zappa.cli:handle",
            "z=zappa.cli:handle",
        ],
    },
    classifiers=[
        "Environment :: Console",
        "License :: OSI Approved :: Apache Software License",
        "Operating System :: OS Independent",
        "Programming Language :: Python",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "Programming Language :: Python :: 3.13",
        "Framework :: Django",
        "Framework :: Django :: 4.2",
        "Framework :: Django :: 5.2",
        "Topic :: Internet :: WWW/HTTP",
        "Topic :: Internet :: WWW/HTTP :: Dynamic Content",
    ],
)
