"""Configuration to connect to a PostgreSQL database."""

# Standard Python Libraries
from configparser import ConfigParser
import platform

# Third-Party Libraries
from importlib_resources import files

REPORT_DB_CONFIG = files("pe_reports").joinpath("data/database.ini")


if platform.system() == "Darwin":

    def config(filename=REPORT_DB_CONFIG, section="postgresql"):
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

else:

    def config(filename=REPORT_DB_CONFIG, section="postgres"):
        """Parse Postgres configuration details from database configuration file."""
        parser = ConfigParser()
        print("running this")
        parser.read(filename, encoding="utf-8")

        db = dict()

        if parser.has_section(section):
            for key, value in parser.items(section):
                db[key] = value

        else:
            raise Exception(f"Section {section} not found in {filename}")

        return db
