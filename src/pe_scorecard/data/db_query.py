#!/usr/bin/env python
"""Query the PE PostgreSQL database."""

# Standard Python Libraries
import logging
import sys

# Third-Party Libraries
import psycopg2
from psycopg2 import OperationalError

from .config import config, staging_config

# Setup logging to central file
LOGGER = logging.getLogger(__name__)

CONN_PARAMS_DIC = config()
CONN_PARAMS_DIC_STAGING = staging_config()


def show_psycopg2_exception(err):
    """Handle errors for PostgreSQL issues."""
    err_type, err_obj, traceback = sys.exc_info()
    LOGGER.error(
        "Database connection error: %s on line number: %s", err, traceback.tb_lineno
    )


def connect():
    """Connect to PostgreSQL database."""
    conn = None
    try:
        conn = psycopg2.connect(**CONN_PARAMS_DIC)
    except OperationalError as err:
        print(err)
        show_psycopg2_exception(err)
        conn = None
    return conn


def close(conn):
    """Close connection to PostgreSQL."""
    conn.close()
    return


def query_https_scan(month, agency):
    """Query https scan results for a given agency and month."""


def query_sslyze_scan(month, agency):
    """Query sslyze scan results for a given agency and month."""
    # "domain", "scanned_port", "scanned_hostname", "sslv2", "sslv3", "any_3des", "any_rc4", "is_symantec_cert


def query_subs_https_scan(base_domain):
    """Query sub_domain sslyze scan results for a given root_domain."""


#  self.__db.https_scan.find(
#                         {
#                             "latest": True,
#                             "base_domain": domain_doc["base_domain"],
#                             "is_base_domain": False,
#                         }
#                     ).sort([("domain", 1)])


def query_trusty_mail(month, agency):
    """Query trusty mail scan results for a given agency and month."""
    # all_domains_cursor = self.__db.trustymail.find(
    #         {"latest": True, "agency.name": agency}, no_cursor_timeout=True
    #     )
