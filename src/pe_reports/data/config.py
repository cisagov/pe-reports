"""Configuration to connect to a PostgreSQL database."""

# Standard Python Libraries
from configparser import ConfigParser
import os

# Third-Party Libraries
from importlib_resources import files

REPORT_DB_CONFIG = files("pe_reports").joinpath("data/database.ini")


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


def staging_config(filename=REPORT_DB_CONFIG, section="staging"):
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


def whois_xml_api_key():
    """Fetch the WhoisXML API key."""
    section = "whoisxml"
    if os.path.isfile(REPORT_DB_CONFIG):
        parser = ConfigParser()
        parser.read(REPORT_DB_CONFIG, encoding="utf-8")
        if parser.has_section(section):
            params = parser.items(section)
            _key = params[0]
            key = _key[1]
        else:
            raise Exception(
                "Section {} not found in the {} file".format(section, REPORT_DB_CONFIG)
            )
    else:
        raise Exception(
            "Database.ini file not found at this path: {}".format(REPORT_DB_CONFIG)
        )
    return key


def db_password_key(filename=REPORT_DB_CONFIG, section="pe_db_password_key"):
    """Get key to encrypt/decrypt P&E passwords."""
    parser = ConfigParser()
    parser.read(filename, encoding="utf-8")
    dict = dict()
    if parser.has_section(section):
        for key, value in parser.items(section):
            dict[key] = value
    else:
        raise Exception(f"Section {section} not found in {filename}")
    return dict["key"]
