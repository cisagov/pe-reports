"""Get cybersixgill API token."""

# Standard Python Libraries
from configparser import ConfigParser
import os

# Third-Party Libraries
from importlib_resources import files
import requests

# Configuration
SECTION = "sixgill"
REPORT_DB_CONFIG = files("pe_reports").joinpath("data/database.ini")


def token():
    """Retrieve bearer token from Cybersixgill client."""
    if os.path.isfile(REPORT_DB_CONFIG):
        parser = ConfigParser()
        parser.read(REPORT_DB_CONFIG, encoding="utf-8")
        if parser.has_section(SECTION):
            params = parser.items(SECTION)
            _id, _secret = params[0], params[1]
            client_id = _id[1]
            client_secret = _secret[1]
        else:
            raise Exception(
                "Section {} not found in the {} file".format(SECTION, REPORT_DB_CONFIG)
            )
    else:
        raise Exception(
            "Database.ini file not found at this path: {}".format(REPORT_DB_CONFIG)
        )
    url = "https://api.cybersixgill.com/auth/token/"
    headers = {
        "Content-Type": "application/x-www-form-urlencoded",
        "Cache-Control": "no-cache",
    }
    payload = {
        "grant_type": "client_credentials",
        "client_id": client_id,
        "client_secret": client_secret,
    }
    resp = requests.post(url, headers=headers, data=payload).json()
    return resp["access_token"]
