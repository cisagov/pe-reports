"""Get PE Source API credentials."""

# Standard Python Libraries
from configparser import ConfigParser
import logging
import os

# Third-Party Libraries
from importlib_resources import files
import requests
import shodan

# Configuration
REPORT_DB_CONFIG = files("pe_reports").joinpath("data/database.ini")


# Setup logging to central file
# To avoid a circular reference error which occurs when calling app.config["LOGGER"]
# we are directly calling the logger here
LOGGER = logging.getLogger(__name__)


def shodan_api_init():
    """Connect to Shodan API."""
    section = "shodan"
    api_list = []
    if not os.path.isfile(REPORT_DB_CONFIG):
        raise Exception(f"Database.ini file not found at this path: {REPORT_DB_CONFIG}")

    with open(REPORT_DB_CONFIG, encoding="utf-8") as config_file:
        parser = ConfigParser()
        parser.read_file(config_file)
        if not parser.has_section(section):
            raise Exception(
                f"Section {section} not found in the {REPORT_DB_CONFIG} file"
            )
        params = parser.items(section)

    for key, value in params:
        try:
            api = shodan.Shodan(value)
            # Test api key
            api.info()
            api_list.append(api)
        except shodan.APIError as e:
            LOGGER.error(f"Invalid Shodan API key: {key} ({e})")

    LOGGER.info(f"Number of valid Shodan API keys: {len(api_list)}")
    return api_list


def cybersix_token():
    """Retrieve bearer token from Cybersixgill client."""
    section = "sixgill"
    if os.path.isfile(REPORT_DB_CONFIG):
        parser = ConfigParser()
        parser.read(REPORT_DB_CONFIG, encoding="utf-8")
        if parser.has_section(section):
            params = parser.items(section)
            _id, _secret = params[0], params[1]
            client_id = _id[1]
            client_secret = _secret[1]
        else:
            raise Exception(
                "Section {} not found in the {} file".format(section, REPORT_DB_CONFIG)
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


def get_params(section):
    """Get data source parameters."""
    if os.path.isfile(REPORT_DB_CONFIG):
        parser = ConfigParser()
        parser.read(REPORT_DB_CONFIG, encoding="utf-8")
        if parser.has_section(section):
            params = parser.items(section)
        else:
            raise Exception(
                "Section {} not found in the {} file".format(section, REPORT_DB_CONFIG)
            )
    else:
        raise Exception(
            "Database.ini file not found at this path: {}".format(REPORT_DB_CONFIG)
        )
    return params