"""
This is the setup module for the pe-reports project.

Based on:

- https://packaging.python.org/distributing/
- https://github.com/pypa/sampleproject/blob/master/setup.py
- https://blog.ionelmc.ro/2014/05/25/python-packaging/#the-structure
"""

# Standard Python Libraries
import codecs
from glob import glob
from os.path import abspath, basename, dirname, join, splitext

# Third-Party Libraries
from setuptools import find_packages, setup


def readme():
    """Read in and return the contents of the project's README.md file."""
    with open("README.md", encoding="utf-8") as f:
        return f.read()


# Below two methods were pulled from:
# https://packaging.python.org/guides/single-sourcing-package-version/
def read(rel_path):
    """Open a file for reading from a given relative path."""
    here = abspath(dirname(__file__))
    with codecs.open(join(here, rel_path), "r") as fp:
        return fp.read()


def get_version(version_file):
    """Extract a version number from the given file path."""
    for line in read(version_file).splitlines():
        if line.startswith("__version__"):
            delim = '"' if '"' in line else "'"
            return line.split(delim)[1]
    raise RuntimeError("Unable to find version string.")


setup(
    name="pe_reports",
    # Versions should comply with PEP440
    version=get_version("src/pe_reports/_version.py"),
    description="Posture and Exposure Reports library",
    long_description=readme(),
    long_description_content_type="text/markdown",
    # Landing page for CISA's cybersecurity mission
    url="https://www.cisa.gov/cybersecurity",
    # Additional URLs for this project per
    # https://packaging.python.org/guides/distributing-packages-using-setuptools/#project-urls
    project_urls={
        "Source": "https://github.com/cisagov/pe-reports",
        "Tracker": "https://github.com/cisagov/pe-reports/issues",
    },
    # Author details
    author="Cybersecurity and Infrastructure Security Agency",
    author_email="github@cisa.dhs.gov",
    license="License :: CC0 1.0 Universal (CC0 1.0) Public Domain Dedication",
    # See https://pypi.python.org/pypi?%3Aaction=list_classifiers
    classifiers=[
        # How mature is this project? Common values are
        #   3 - Alpha
        #   4 - Beta
        #   5 - Production/Stable
        "Development Status :: 3 - Alpha",
        # Indicate who your project is intended for
        "Intended Audience :: Developers",
        # Pick your license as you wish (should match "license" above)
        "License :: CC0 1.0 Universal (CC0 1.0) Public Domain Dedication",
        # Specify the Python versions you support here. In particular, ensure
        # that you indicate whether you support Python 2, Python 3 or both.
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3 :: Only",
        "Programming Language :: Python :: 3.6",
        "Programming Language :: Python :: 3.7",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        # Temporarily hold back support for Python 3.11 due to the version pin
        # for the PyMuPDF package. Pre-built wheels for Python 3.11 were not made
        # available until the 1.21.0 release and building the PyMuPDF package from
        # source proves problematic due to dependencies. Please see the following
        # issue for more information: https://github.com/cisagov/pe-reports/issues/441
        # "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: Implementation :: CPython",
    ],
    python_requires=">=3.6",
    # What does your project relate to?
    keywords="posture and exposure report",
    packages=find_packages(where="src"),
    package_dir={"": "src"},
    package_data={
        "pe_mailer": ["data/*"],
        "pe_reports": ["data/shell/*.pptx", "data/*.ini", "helpers/*"],
        "pe_source": ["data/*", "data/shodan/*", "data/sixgill/*", "data/pe_db/*"],
    },
    py_modules=[splitext(basename(path))[0] for path in glob("src/*.py")],
    include_package_data=True,
    install_requires=[
        "boto3 == 1.26.105",
        "botocore == 1.24.10",
        "chevron == 0.14.0",
        "celery",
        "click",
        "dnstwist",
        "docopt",
        "DShield",
        "glob2 == 0.7",
        "flask",
        "flask",
        "flask_login",
        "flask_migrate",
        "flask_wtf",
        "Flask-SQLAlchemy",
        "importlib_metadata == 4.8.3",
        "importlib_resources == 5.4.0",
        "matplotlib == 3.3.4",
        "mongo-db-from-config@http://github.com/cisagov/mongo-db-from-config/tarball/develop",
        "openpyxl",
        "pandas == 1.1.5",
        "pdfkit",
        "psutil",
        "psycopg2-binary == 2.9.3",
        "pymongo == 4.0.1",
        "pymupdf == 1.19.0",
        "python-dateutil >= 2.7.3",
        "pytest-cov",
        "python-pptx == 0.6.21",
        "pytz",
        "pyyaml == 6.0",
        "reportlab == 3.6.6",
        "requests == 2.26.0",
        "schema == 0.7.5",
        "setuptools == 58.1.0",
        "shodan ==1.27.0",
        "sublist3r",
        "types-PyYAML == 6.0.4",
        "urllib3 == 1.26.7",
        "wtforms",
        "xhtml2pdf == 0.2.5",
    ],
    extras_require={
        "test": [
            "coverage",
            # coveralls 1.11.0 added a service number for calls from
            # GitHub Actions. This caused a regression which resulted in a 422
            # response from the coveralls API with the message:
            # Unprocessable Entity for url: https://coveralls.io/api/v1/jobs
            # 1.11.1 fixed this issue, but to ensure expected behavior we'll pin
            # to never grab the regression version.
            "coveralls != 1.11.0",
            "pre-commit",
            "pytest-cov",
            "pytest",
        ]
    },
    # Conveniently allows one to run the CLI tool as `pe-reports` or 'pe-mailer'
    entry_points={
        "console_scripts": [
            "pe-mailer = pe_mailer.email_reports:main",
            "pe-reports = pe_reports.report_generator:main",
            "pe-source = pe_source.pe_scripts:main",
        ]
    },
)
