"""Configuration to connect to a PostgreSQL database."""

# Standard Python Libraries
from configparser import ConfigParser

# Third-Party Libraries
from importlib.resources import files

REPORT_DB_CONFIG = files("pe_reports").joinpath("data/dbconfig.config")



def config(filename=REPORT_DB_CONFIG, section="postgres"):
    """Configure connection to creds file and returns creds."""
    parser = ConfigParser()

    parser.read(filename, encoding="utf-8")

    db = dict()

    if parser.has_section(section):
        for key, value in parser.items(section):
            db[key] = value

    else:
        raise Exception(f"Section {section} not found in {filename}")

    return db
