"""Configure database connection."""
# Standard Python Libraries
from configparser import ConfigParser
import os


def config(
    filename="/var/www/pe-reports/src/pe_reports/data/database.ini", section="postgres"
):
    """Configure postgres."""
    # create a parser
    parser = ConfigParser()
    # read config file
    parser.read(filename)

    # get section, default to postgresql
    db = {}
    if parser.has_section(section):
        params = parser.items(section)
        for param in params:
            db[param[0]] = param[1]
    else:
        raise Exception("Section {} not found in the {} file".format(section, filename))
    return db


def config2(filename="/home/ubuntu/adhoc/data/database.ini", section="crossfeedDB"):
    """Configure Crossfeed."""
    # create a parser
    parser = ConfigParser()
    # read config file
    parser.read(filename)

    # get section, default to postgresql
    db = {}
    if parser.has_section(section):
        params = parser.items(section)
        for param in params:
            db[param[0]] = param[1]
    else:
        raise Exception("Section {} not found in the {} file".format(section, filename))
    return db


def get_hibp_token(
    filename="/var/www/pe-reports/src/pe_reports/data/database.ini", section="hibp"
):
    if os.path.isfile(filename):
        parser = ConfigParser()
        parser.read(filename, encoding="utf-8")
        if parser.has_section(section):
            params = parser.items(section)
            _key = params[0]
            key = _key[1]
        else:
            raise Exception(
                "Section {} not found in the {} file".format(section, filename)
            )
    else:
        raise Exception("Database.ini file not found at this path: {}".format(filename))
    return key
