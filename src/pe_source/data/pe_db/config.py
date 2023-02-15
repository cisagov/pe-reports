"""Get PE Source API credentials."""

# Standard Python Libraries
from configparser import ConfigParser
import logging
import os
import time

# Third-Party Libraries
from importlib_resources import files
import requests
import shodan

# Configuration
REPORT_DB_CONFIG = files("pe_source").joinpath("data/database.ini")

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
    
def shodan_api_init():
    """Connect to Shodan API."""
    section = "shodan"
    api_list = []
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

    for key in params:
        try:
            api = shodan.Shodan(key[1])
            # Test api key
            api.info()
        except Exception:
            logging.error("Invalid Shodan API key: {}".format(key))
            continue
        api_list.append(api)
    logging.info("Number of valid Shodan API keys: {}".format(len(api_list)))
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
    count = 1
    while count < 15:
        try:
            resp = requests.post(url, headers=headers, data=payload).json()
            break
        except Exception as e:
            logging.info("Error. Trying token post again...")
            time.sleep(10)
            count += 1
            continue

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


def dnsmonitor_token():
    """Retreive the DNSMonitor bearer token."""
    section = "dnsmonitor"
    params = get_params(section)
    client_id, client_secret = params[0][1], params[1][1]
    scope = "DNSMonitorAPI"
    url = "https://argosecure.com/dhs/connect/token"

    payload = {
        "client_id": client_id,
        "client_secret": client_secret,
        "grant_type": "client_credentials",
        "scope": scope,
    }
    headers = {}
    files = []
    response = requests.request(
        "POST", url, headers=headers, data=payload, files=files
    ).json()
    return response["access_token"]
