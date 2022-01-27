"""Get cybersixgill API token."""

# Standard Python Libraries
from configparser import ConfigParser
import glob
import os

# Third-Party Libraries
import requests

# Configuration
SECTION = "sixgill"
BASE_DIR = os.path.abspath(os.path.join(__file__, "../../../.."))
REPORT_DB_CONFIG = glob.glob(f"{BASE_DIR}/**/*.ini", recursive=True)[0]


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
        raise Exception("Database.ini file not found.")
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
    token = resp["access_token"]
    return token
