"""Configuration to connect to a PostgreSQL database."""

# Standard Python Libraries
from configparser import ConfigParser
import glob
import os

BASE_DIR = os.path.abspath(os.path.join(__file__, "../../../.."))
REPORT_DB_CONFIG = glob.glob(f"{BASE_DIR}/**/*.ini", recursive=True)


def config(filename=REPORT_DB_CONFIG, section="postgres"):
    """Parse Postgres configuration details from database configuration file."""
    parser = ConfigParser()

    if len(filename) > 0:
        parser.read(filename[0], encoding="utf-8")

        db = dict()

        if parser.has_section(section):
            for key, value in parser.items(section):
                db[key] = value

        else:
            raise Exception("Section %s not found in %s", section, filename)
    else:
        raise Exception("File of type .ini not found.")

    return db
