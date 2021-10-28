#!/usr/bin/python3


"""This module contains the postgresql dbconfig.config code."""

from configparser import ConfigParser

# Third-Party Libraries
import pkg_resources


REPORT_DB_CONFIG = pkg_resources.resource_filename("pe_reports", "data/dbconfig.config")


def config(filename=REPORT_DB_CONFIG, section='postgres'):

    """Reads .config file that contains DB credentials.

    """

    parser = ConfigParser()

    parser.read(filename, encoding='utf-8')

    db = {}

    if parser.has_section(section):
        params = parser.items(section)

        for param in params:
            db[param[0]] = param[1]

    else:
        raise Exception(f'Section {section} not found in {filename}')

    return db





