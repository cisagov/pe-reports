"""Get cybersixgill API token."""

# Standard Python Libraries
from configparser import ConfigParser
import glob
import logging
import os

# Third-Party Libraries
import shodan

# Configuration
SECTION = "shodan"
BASE_DIR = os.path.abspath(os.path.join(__file__, "../../../.."))
REPORT_DB_CONFIG = glob.glob(f"{BASE_DIR}/**/*.ini", recursive=True)[0]


def api_init():
    """Connect to shodan API."""
    api_list = []
    if os.path.isfile(REPORT_DB_CONFIG):
        parser = ConfigParser()
        parser.read(REPORT_DB_CONFIG, encoding="utf-8")
        if parser.has_section(SECTION):
            params = parser.items(SECTION)
        else:
            raise Exception(
                "Section {} not found in the {} file".format(SECTION, REPORT_DB_CONFIG)
            )
    else:
        raise Exception("Config.ini file not found.")

    for key in params:
        try:
            api = shodan.Shodan(key[1])
            # Test api key
            api.info()
        except Exception:
            logging.error(f"Invalid API key: {key}")
            continue
        api_list.append(api)
    logging.info(f"Number of valid API keys: {len(api_list)}")
    return api_list
