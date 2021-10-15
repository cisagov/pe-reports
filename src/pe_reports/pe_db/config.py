"""Configure database."""
# !/usr/bin/python
# Standard Python Libraries
from configparser import ConfigParser


def config(
    filename="/Users/loftusa/Documents/PE/Scripts/final_report_v1.0.0/pe-reports/src/pe_reports/pe_db/data/database.ini",
    section="postgresql",
):
    """Configure database."""
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
