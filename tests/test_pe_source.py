"""Tests for the pe-source module."""

# Standard Python Libraries
import logging
import sys
from unittest.mock import patch

# Third-Party Libraries
import pytest

# cisagov Libraries
from pe_reports import CENTRAL_LOGGING_FILE
import pe_source.pe_scripts

log_levels = (
    "debug",
    "info",
    "warning",
    "error",
    "critical",
)

# Setup logging to file
logging.basicConfig(
    filename=CENTRAL_LOGGING_FILE,
    filemode="a",
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    datefmt="%m/%d/%Y %I:%M:%S",
    level="INFO",
)

logger = logging.getLogger(__name__)


PROJECT_VERSION = pe_source.__version__


# TODO: Replace current dummy test with useful tests
# Issue - https://github.com/cisagov/pe-reports/issues/3#issue-909531010


def test_source_stdout_version(capsys):
    """Verify that version string sent to stdout agrees with the module version."""
    with pytest.raises(SystemExit):
        with patch.object(sys, "argv", ["bogus", "--version"]):
            pe_source.pe_scripts.main()
    captured = capsys.readouterr()
    assert (
        captured.out == f"{PROJECT_VERSION}\n"
    ), "standard output by '--version' should agree with module.__version__"


def test_source_running_as_module(capsys):
    """Verify that the __main__.py file loads correctly."""
    with pytest.raises(SystemExit):
        with patch.object(sys, "argv", ["bogus", "--version"]):
            # F401 is a "Module imported but unused" warning. This import
            # emulates how this project would be run as a module. The only thing
            # being done by __main__ is importing the main entrypoint of the
            # package and running it, so there is nothing to use from this
            # import. As a result, we can safely ignore this warning.
            # cisagov Libraries
            import pe_source.__main__  # noqa: F401
    captured = capsys.readouterr()
    assert (
        captured.out == f"{PROJECT_VERSION}\n"
    ), "standard output by '--version' should agree with module.__version__"


@pytest.mark.parametrize("level", log_levels)
def test_source_log_levels(level):
    """Validate commandline log-level arguments."""
    with patch.object(
        sys,
        "argv",
        [
            "pe-source",
            "source",
            f"--log-level={level}",
        ],
    ):
        with patch.object(logging.root, "handlers", []):
            assert (
                logging.root.hasHandlers() is False
            ), "root logger should not have handlers yet"
            return_code = None
            try:
                pe_source.pe_scripts.main()
            except SystemExit as sys_exit:
                return_code = sys_exit.code
            assert (
                logging.root.hasHandlers() is True
            ), "root logger should now have a handler"
            assert (
                logging.getLevelName(logging.root.getEffectiveLevel()) == level.upper()
            ), f"root logger level should be set to {level.upper()}"
            assert return_code is None, "main() should return success"


def test_source_bad_log_level():
    """Validate bad log-level argument returns error."""
    with patch.object(
        sys,
        "argv",
        [
            "pe-source",
            "source",
            "--log-level=emergency",
        ],
    ):
        return_code = None
        try:
            pe_source.pe_scripts.main()
        except SystemExit as sys_exit:
            return_code = sys_exit.code
        assert return_code == 1, "main() should exit with error"
