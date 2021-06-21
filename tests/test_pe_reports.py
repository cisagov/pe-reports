"""File to be used to create test for pe-reports."""

# Standard Python Libraries
import logging
import sys
from unittest.mock import patch

# Third-Party Libraries
import pytest

# cisagov Libraries
import pe_reports.report_generator

log_levels = (
    "debug",
    "info",
    "warning",
    "error",
    "critical",
)


PROJECT_VERSION = pe_reports.__version__


# TODO: Replace current dummy test with useful tests - https://github.com/cisagov/pe-reports/issues/3#issue-909531010


def test_stdout_version(capsys):
    """Verify that version string sent to stdout agrees with the module version."""
    with pytest.raises(SystemExit):
        with patch.object(sys, "argv", ["bogus", "--version"]):
            pe_reports.report_generator.main()
    captured = capsys.readouterr()
    assert (
        captured.out == f"{PROJECT_VERSION}\n"
    ), "standard output by '--version' should agree with module.__version__"


def test_running_as_module(capsys):
    """Verify that the __main__.py file loads correctly."""
    with pytest.raises(SystemExit):
        with patch.object(sys, "argv", ["bogus", "--version"]):
            # F401 is a "Module imported but unused" warning. This import
            # emulates how this project would be run as a module. The only thing
            # being done by __main__ is importing the main entrypoint of the
            # package and running it, so there is nothing to use from this
            # import. As a result, we can safely ignore this warning.
            # cisagov Libraries
            import pe_reports.__main__  # noqa: F401
    captured = capsys.readouterr()
    assert (
        captured.out == f"{PROJECT_VERSION}\n"
    ), "standard output by '--version' should agree with module.__version__"


@pytest.mark.parametrize("level", log_levels)
def test_log_levels(level):
    """Validate commandline log-level arguments."""
    print(level)
    with patch.object(sys, "argv", ["bogus", f"--log-level={level}", "1", "1"]):
        with patch.object(logging.root, "handlers", []):
            assert (
                logging.root.hasHandlers() is False
            ), "root logger should not have handlers yet"
            return_code = pe_reports.report_generator.main()
            assert (
                logging.root.hasHandlers() is True
            ), "root logger should now have a handler"
            assert return_code == 0, "main() should return success (0)"
