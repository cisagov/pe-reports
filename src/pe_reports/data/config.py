"""Configuration to connect to a PostgreSQL database."""

# Standard Python Libraries
from configparser import ConfigParser
import os

basedir = os.path.abspath(os.path.dirname(__file__))
REPORT_DB_CONFIG = os.path.join(basedir, "database.ini")


def config(filename=REPORT_DB_CONFIG, section="postgres"):
    """Parse Postgres configuration details from database configuration file."""
    parser = ConfigParser()

    parser.read(filename, encoding="utf-8")

    db = dict()

    if parser.has_section(section):
        for key, value in parser.items(section):
            db[key] = value

    else:
        raise Exception(f"Section {section} not found in {filename}")

    return db
