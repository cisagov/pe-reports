"""A tool for gathering pe source data.

Usage:
    pe-source DATA_SOURCE [--log-level=LEVEL] [--orgs=ORG_LIST] [--cybersix-methods=METHODS]

Arguments:
  DATA_SOURCE                       Source to collect data from. Valid values are "cybersixgill",
                                    "dnstwist", "hibp", and "shodan".

Options:
  -h --help                         Show this message.
  -v --version                      Show version information.
  -l --log-level=LEVEL              If specified, then the log level will be set to
                                    the specified value.  Valid values are "debug", "info",
                                    "warning", "error", and "critical". [default: info]
  -o --orgs=ORG_LIST                A comma-separated list of orgs to collect data for.
                                    If not specified, data will be collected for all
                                    orgs in the pe database. Orgs in the list must match the
                                    IDs in the cyhy-db. E.g. DHS,DHS_ICE,DOC
                                    [default: all]
  -csg --cybersix-methods=METHODS   A comma-separated list of cybersixgill methods to run.
                                    If not specified, all will run. Valid values are "alerts",
                                    "credentials", "mentions", "topCVEs". E.g. alerts,mentions.
                                    [default: all]
"""

# Standard Python Libraries
import logging
import sys
from typing import Any, Dict

# Third-Party Libraries
import docopt
from schema import And, Schema, SchemaError, Use

from ._version import __version__
from .cybersixgill import Cybersixgill
from .shodan import Shodan


def run_pe_script(source, orgs_list, cybersix_methods):
    """Collect data from the source specified."""
    # If not "all", separate orgs string into a list of orgs
    if orgs_list != "all":
        orgs_list = orgs_list.split(",")
    # If not "all", separate Cybersixgill methods string into a list.
    # See Cybersixgill run_cybersixgillkim
    if cybersix_methods == "all":
        cybersix_methods = [
            "alerts",
            "mentions",
            "credentials",
            "topCVEs",
            "topic_count",
        ]
    else:
        cybersix_methods = cybersix_methods.split(",")

    logging.info("Running %s on these orgs: %s", source, orgs_list)

    if source == "cybersixgill":
        cybersix = Cybersixgill(orgs_list, cybersix_methods)
        cybersix.run_cybersixgill()
    elif source == "shodan":
        shodan = Shodan(orgs_list)
        shodan.run_shodan()


def main():
    """Set up logging and call the run_pe_script function."""
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
        format="%(asctime)-15s %(levelname)s %(message)s", level=log_level.upper()
    )

    # Run pe script on specified source
    run_pe_script(
        validated_args["DATA_SOURCE"],
        validated_args["--orgs"],
        validated_args["--cybersix-methods"],
    )

    # Stop logging and clean up
    logging.shutdown()
