"""Configure database connection."""
# Standard Python Libraries
from configparser import ConfigParser


def config(filename="/home/ubuntu/adhoc/data/database.ini", section="postgresql"):
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
