"""Configuration to connect to a PostgreSQL database."""

# Standard Python Libraries
from configparser import ConfigParser
import glob
import os

BASE_DIR = os.path.abspath(os.path.join(__file__, "../../../.."))
REPORT_DB_CONFIG = glob.glob(f"{BASE_DIR}/**/*.ini", recursive=True)[0]


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
