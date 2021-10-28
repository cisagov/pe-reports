"""The file contains the postgresql dbconfig.config parsing code."""

# Standard Python Libraries
from configparser import ConfigParser

# Third-Party Libraries
import pkg_resources

REPORT_DB_CONFIG = pkg_resources.resource_filename("pe_reports", "data/dbconfig.config")


def config(filename=REPORT_DB_CONFIG, section="postgres"):
    """Configure connection to creds file and returns creds."""
    parser = ConfigParser()

    parser.read(filename, encoding="utf-8")

    db = {}

    if parser.has_section(section):
        params = parser.items(section)

        for param in params:
            db[param[0]] = param[1]

    else:
        raise Exception(f"Section {section} not found in {filename}")

    return db
