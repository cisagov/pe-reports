"""A tool for gathering pe asm data.

Usage:
    pe-asm-sync TEST [--log-level=LEVEL] [--staging]

Options:
  -h --help                         Show this message.
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
from .helpers.enumerate_subs_from_root import enumerate_and_save_subs
from .helpers.link_subs_and_ips_from_ips import connect_subs_from_ips
from .helpers.link_subs_and_ips_from_subs import connect_ips_from_subs
from .helpers.shodan_dedupe import dedupe


LOGGER = logging.getLogger(__name__)


def run_asm_sync(staging):
    """Collect and sync ASM data."""

    # Run function to fetch and store all CyHy assets in the P&E database
    LOGGER.info("Collecting CyHy assets")
    # get_cyhy_assets(staging)
    LOGGER.info("Finished.")

    # Fill the P&E CIDRs table from CyHy assets
    LOGGER.info("Filling CIDRs.")
    fill_cidrs("all_orgs")
    LOGGER.info("Finished.")

    # Enumerate CIDRs for IPs
    # fill_ips_from_cidrs()

    # Fill root domains from dot gov table
    # TODO

    # Enumerate sub domains from roots
    # enumerate_and_save_subs()

    # Connect subs from ips
    # connect_subs_from_ips()

    # Connect ips from subs
    # connect_ips_from_subs()

    # Run shodan dedupe
    # dedupe()


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
    run_asm_sync(staging)

    # Stop logging and clean up
    logging.shutdown()
