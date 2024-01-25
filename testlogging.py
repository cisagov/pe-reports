"""testlogging module for the pe-reports project."""
# Standard Python Libraries
import logging

CENTRAL_LOGGING_FILE = "pe_reports_logging.log"
DEBUG = False
# Setup Logging
"""Set up logging and call the run_pe_script function."""
if DEBUG is True:
    level = "DEBUG"
else:
    level = "INFO"

logging.basicConfig(
    filename=CENTRAL_LOGGING_FILE,
    filemode="a",
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    datefmt="%m/%d/%Y %I:%M:%S",
    level=level,
)

logging.info("The log is logged")
