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


# # Extract the command-line arguments
# cmd_args = sys.argv[1:]

# # Check if the "--exclude-packages" argument is present
# if "--exclude-packages" in cmd_args:
#     # List the packages you want to exclude
#     excluded_packages = ["pe_mailer", "pe_source", "pe_asm", "pe_scorecard", "pe_reports"]

#     # Remove the excluded packages from the packages list
#     for package in excluded_packages:
#         if package in find_packages(where="src"):
#             find_packages(where="src").remove(package)


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
        "Programming Language :: Python :: 3.6",
        "Programming Language :: Python :: 3.7",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
    ],
    python_requires=">=3.6",
    # What does your project relate to?
    keywords="posture and exposure report",
    packages=find_packages(where="src"),
    package_dir={"": "src"},
    package_data={
        "pe_mailer": ["data/*"],
        "pe_reports": ["*.html", "*.css", "data/*", "assets/*", "*.ttf", "fonts/*"],
        "pe_source": [
            "data/*",
            "data/shodan/*",
            "data/sixgill/*",
            "data/dnsmonitor/*",
            "data/pe_db/*",
        ],
        "pe_asm": ["data/*", "helpers/*", "port_scans/*"],
        "pe_scorecard": ["data/*", "helpers/*", "fonts/*", "scorecard_assets/*"],
        "pshtt": [],
    },
    py_modules=[splitext(basename(path))[0] for path in glob("src/*.py")],
    include_package_data=True,
    install_requires=[
        "beautifulsoup4 == 4.12.2",
        "boto3 == 1.33.4",
        "botocore == 1.33.4",
        "chevron == 0.14.0",
        "celery == 5.3.6",
        "circlify == 0.15.0",
        "click == 8.1.7",
        "demoji == 1.1.0",
        "docopt == 0.6.2",
        "dnstwist == 20230918",
        "dshield == 0.2.1",
        "elastic-apm == 6.19.0",
        "flask == 3.0.0",
        "Flask-Login == 0.6.3",
        "flask_migrate == 4.0.5",
        "flask_wtf == 1.2.1",
        "Flask-SQLAlchemy == 3.1.1",
        "glob2 == 0.7",
        "googletrans == 2.4.0",
        "h11==0.14.0",
        "httpcore==0.17.3",
        "httpx==0.24.1",
        # "idna",
        "importlib_resources == 5.4.0",
        "matplotlib == 3.3.4",
        "nested-lookup == 0.2.25",
        "nltk == 3.8.1",
        "openpyxl == 3.1.2",
        "pandas == 1.1.5",
        "pdfkit ==  1.0.0",
        "psutil == 5.9.6",
        "psycopg2-binary == 2.9.9",
        "publicsuffixlist[update]>=0.9.2 ",
        "pymongo == 4.0.1",
        "pymupdf ==  1.23.7",
        "pyopenssl == 23.3.0",
        "python-dateutil ==   2.8.2",
        "pytest-cov ==  4.1.0",
        "python-pptx == 0.6.21",
        "pytz == 2023.3.post1",
        "pyyaml == 6.0",
        "redis == 5.0.1",
        "reportlab == 4.0.7",
        "requests == 2.31.0",
        "retry ==  0.9.2",
        "schema == 0.7.5",
        "setuptools == 58.1.0",
        "scikit-learn ==  1.3.2",
        "shodan == 1.27.0",
        "spacy == 3.7.2",
        "sshtunnel == 0.4.0",
        "sslyze>=5.0.0",
        "sublist3r ==  1.0",
        "types-PyYAML == 6.0.4",
        "urllib3 == 1.26",
        "wtforms ==  3.1.1",
        "werkzeug == 3.0.1",
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
            "types-pyOpenSSL",
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
            "pe-asm-sync = pe_asm.asm_sync:main",
            "pe-scorecard = pe_scorecard.scorecard_generator:main",
        ]
    },
)
