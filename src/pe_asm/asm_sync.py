"""A tool for gathering pe asm data.

Usage:
    pe-asm-sync METHOD [--log-level=LEVEL] [--staging]

Options:
  -h --help                         Show this message.
  METHOD                            Either scorecard or asm. Which data to collect.
  -v --version                      Show version information.
  -l --log-level=LEVEL              If specified, then the log level will be set to
                                    the specified value.  Valid values are "debug", "info",
                                    "warning", "error", and "critical". [default: info]
  -s --staging                      Run on the staging database. Otherwise will run on a local copy.                             
"""

# Standard Python Libraries
import logging
import sys
from typing import Any, Dict

# Third-Party Libraries
import docopt
from schema import And, Schema, SchemaError, Use

# cisagov Libraries
import pe_reports
from ._version import __version__
from .helpers.get_cyhy_assets import get_cyhy_assets
from .helpers.fill_cidrs_from_cyhy_assets import fill_cidrs
from .helpers.fill_ips_from_cidrs import fill_ips_from_cidrs
from .helpers.enumerate_subs_from_root import get_subdomains
from .helpers.link_subs_and_ips_from_ips import connect_subs_from_ips
from .helpers.link_subs_and_ips_from_subs import connect_ips_from_subs
from .helpers.shodan_dedupe import dedupe
from .helpers.get_cyhy_scorecard_data import (
    get_cyhy_snapshots,
    get_cyhy_tickets,
    get_cyhy_vuln_scans,
    get_cyhy_kevs,
    get_cyhy_https_scan,
    get_cyhy_trustymail,
    get_cyhy_sslyze,
)
from .helpers.query_cyhy_port_scans import get_cyhy_port_scans
from .data.cyhy_db_query import (
    pe_db_connect,
    pe_db_staging_connect,
    identify_ip_changes,
    identify_sub_changes,
    identify_ip_sub_changes,
)


LOGGER = logging.getLogger(__name__)


def run_asm_sync(staging, method):
    """Collect and sync ASM data."""

    if method == "asm":
        # Run function to fetch and store all CyHy assets in the P&E database
        LOGGER.info("Collecting CyHy assets")
        get_cyhy_assets(staging)
        LOGGER.info("Finished.")

        # Fill the P&E CIDRs table from CyHy assets
        LOGGER.info("Filling CIDRs.")
        fill_cidrs("all_orgs", staging)
        LOGGER.info("Finished.")

        # Enumerate CIDRs for IPs
        LOGGER.info("Filling IPs from CIDRs.")
        fill_ips_from_cidrs(staging)
        LOGGER.info("Finished.")

        # Fill root domains from dot gov table
        # TODO

        # Enumerate sub domains from roots
        LOGGER.info("Enumerating roots and saving sub-domains.")
        get_subdomains(staging)
        LOGGER.info("Finished.")

        # Connect subs from ips
        LOGGER.info("Linking subs from ips.")
        connect_subs_from_ips(staging)
        LOGGER.info("Finished.")

        # Connect ips from subs
        LOGGER.info("Linking ips from subs.")
        connect_ips_from_subs(staging)
        LOGGER.info("Finished.")

        # Identify the current IPs, sub-domains, and connections
        if staging:
            conn = pe_db_staging_connect()
        else:
            conn = pe_db_connect()
        LOGGER.info("Identify changes.")
        identify_ip_changes(conn)
        identify_sub_changes(conn)
        identify_ip_sub_changes(conn)
        conn.close()
        LOGGER.info("Finished")

        # Run shodan dedupe
        LOGGER.info("Running Shodan dedupe.")
        dedupe(staging)
        LOGGER.info("Finished.")

    elif method == "scorecard":

        LOGGER.info("STARTING")
        get_cyhy_port_scans(staging)
        # get_cyhy_snapshots(staging)
        # get_cyhy_tickets(staging)
        # get_cyhy_vuln_scans(staging)
        # get_cyhy_kevs(staging)
        # get_cyhy_https_scan(staging)
        # get_cyhy_trustymail(staging)
        # get_cyhy_sslyze(staging)
        LOGGER.info("FINISHED")

    else:
        LOGGER.error(
            "In command please specify either 'scorecard' or 'asm'. i.e. pe-asm-sync scorecard"
        )


def main():
    """Set up logging and call the run_asm_sync function."""
    args: Dict[str, str] = docopt.docopt(__doc__, version=__version__)
    # Validate and convert arguments as needed
    schema: Schema = Schema(
        {
            "--log-level": And(
                str,
                Use(str.lower),
                lambda n: n in ("debug", "info", "warning", "error", "critical"),
                error="Possible values for --log-level are "
                + "debug, info, warning, error, and critical.",
            ),
            str: object,  # Don't care about other keys, if any
        }
    )

    try:
        validated_args: Dict[str, Any] = schema.validate(args)
    except SchemaError as err:
        # Exit because one or more of the arguments were invalid
        print(err, file=sys.stderr)
        sys.exit(1)

    # Assign validated arguments to variables
    log_level: str = validated_args["--log-level"]

    # Set up logging
    logging.basicConfig(
        filename=pe_reports.CENTRAL_LOGGING_FILE,
        filemode="a",
        format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
        datefmt="%m/%d/%Y %I:%M:%S",
        level=log_level.upper(),
    )
    LOGGER.info("Starting ASM sync scripts")

    # Check for the staging option
    try:
        staging = validated_args["--staging"]
    except:
        staging = False

    # Run ASM finder
    run_asm_sync(staging, validated_args["METHOD"])

    # Stop logging and clean up
    logging.shutdown()
