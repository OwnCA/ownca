#!/usr/bin/env python

# pip still might require a setup.py file to support ...
# editable installs (PEP 660)
# https://setuptools.pypa.io/en/latest/userguide/pyproject_config.html
# keep this file until it does

import os
import sys
from codecs import open

from setuptools import setup
from setuptools.command.test import test as TestCommand

here = os.path.abspath(os.path.dirname(__file__))

packages = ["ownca", "ownca/crypto"]
requires = ["cryptography<35.0.0,>=3.4.6", "voluptuous>=0.11.7"]
test_requirements = ["pytest>=3"]
about = {}


class PyTest(TestCommand):
    user_options = [("pytest-args=", "a", "Arguments to pass into py.test")]

    def initialize_options(self):
        TestCommand.initialize_options(self)

        try:
            from multiprocessing import cpu_count

            self.pytest_args = ["-n", str(cpu_count()), "--boxed"]

        except (ImportError, NotImplementedError):
            self.pytest_args = ["-n", "1", "--boxed"]

    def finalize_options(self):
        TestCommand.finalize_options(self)
        self.test_args = []
        self.test_suite = True

    def run_tests(self):
        import pytest

        errno = pytest.main(self.pytest_args)
        sys.exit(errno)


# 'setup.py publish' shortcut.
if sys.argv[-1] == "publish":
    os.system("python setup.py sdist bdist_wheel")
    os.system("twine upload dist/*")
    sys.exit()

with open(os.path.join(here, "ownca", "__version__.py"), "r", "utf-8") as f:
    exec(f.read(), about)

with open("README.md", "r", "utf-8") as f:
    readme = f.read()

with open("HISTORY.md", "r", "utf-8") as f:
    history = f.read()

setup(
    name=about["__title__"],
    version=about["__version__"],
    description=about["__description__"],
    long_description=readme,
    long_description_content_type="text/markdown",
    author=about["__author__"],
    author_email=about["__author_email__"],
    url=about["__url__"],
    packages=packages,
    package_data={"": ["LICENSE", "NOTICE"], "ownca": ["*.pem"]},
    package_dir={"ownca": "ownca"},
    include_package_data=True,
    python_requires=">=3.7",
    install_requires=requires,
    license=about["__license__"],
    zip_safe=False,
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Developers",
        "Natural Language :: English",
        "License :: OSI Approved :: Apache Software License",
        "Programming Language :: Python",
        "Programming Language :: Python :: 3.7",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: Implementation :: CPython",
        "Programming Language :: Python :: Implementation :: PyPy",
    ],
    cmdclass={"test": PyTest},
    tests_require=test_requirements,
    extras_require={},
    project_urls={
        "Documentation": "https://ownca.readthedocs.io",
        "Source": "https://github.com/OwnCa/ownca"
    },
)
