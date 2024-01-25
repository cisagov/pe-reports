#!/usr/bin/python3
"""This module contains the pastgresql dbconfig.config code."""

# Standard Python Libraries
from configparser import ConfigParser

# Third-Party Libraries
from importlib_resources import files

REPORT_DB_CONFIG = files("pe_reports").joinpath("data/database.ini")


def db_config(filename=REPORT_DB_CONFIG, section="postgres"):
    """Get credentials for P&E postgres database."""
    parser = ConfigParser()
    parser.read(filename, encoding="utf-8")
    db = dict()
    if parser.has_section(section):
        for key, value in parser.items(section):
            if key == "pe_api_key" or key == "pe_api_url":
                continue
            db[key] = value
    else:
        raise Exception(f"Section {section} not found in {filename}")
    return db


def db_password_key(filename=REPORT_DB_CONFIG, section="pe_db_password_key"):
    """Get key to encrypt/decrypt P&E passwords."""
    parser = ConfigParser()
    parser.read(filename, encoding="utf-8")
    db = dict()
    if parser.has_section(section):
        for key, value in parser.items(section):
            db[key] = value
    else:
        raise Exception(f"Section {section} not found in {filename}")
    return db["key"]
