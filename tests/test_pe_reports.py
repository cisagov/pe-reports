"""File to be used to create test for pe-reports."""

# Standard Python Libraries
import logging
import sys
from unittest.mock import patch

# Third-Party Libraries
import pytest

# cisagov Libraries
from pe_reports import app as flask_app
import pe_reports.report_generator

log_levels = (
    "debug",
    "info",
    "warning",
    "error",
    "critical",
)


PROJECT_VERSION = pe_reports.__version__


# TODO: Replace current dummy test with useful tests
# Issue - https://github.com/cisagov/pe-reports/issues/3#issue-909531010


def test_reports_stdout_version(capsys):
    """Verify that version string sent to stdout agrees with the module version."""
    with pytest.raises(SystemExit):
        with patch.object(sys, "argv", ["bogus", "--version"]):
            pe_reports.report_generator.main()
    captured = capsys.readouterr()
    assert (
        captured.out == f"{PROJECT_VERSION}\n"
    ), "standard output by '--version' should agree with module.__version__"


def test_reports_running_as_module(capsys):
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
def test_reports_log_levels(level):
    """Validate commandline log-level arguments."""
    with patch.object(
        sys,
        "argv",
        [
            "pe-reports",
            "2021-01-01",
            "output/",
            f"--log-level={level}",
        ],
    ):
        with patch.object(logging.root, "handlers", []):
            assert (
                logging.root.hasHandlers() is False
            ), "root logger should not have handlers yet"
            return_code = None
            try:
                pe_reports.report_generator.main()
            except SystemExit as sys_exit:
                return_code = sys_exit.code
            assert (
                logging.root.hasHandlers() is True
            ), "root logger should now have a handler"
            assert (
                logging.getLevelName(logging.root.getEffectiveLevel()) == level.upper()
            ), f"root logger level should be set to {level.upper()}"
            assert return_code is None, "main() should return success"


def test_reports_bad_log_level():
    """Validate bad log-level argument returns error."""
    with patch.object(
        sys,
        "argv",
        [
            "pe-reports",
            "2021-01-01",
            "output/",
            "--log-level=emergency",
        ],
    ):
        return_code = None
        try:
            pe_reports.report_generator.main()
        except SystemExit as sys_exit:
            return_code = sys_exit.code
        assert return_code == 1, "main() should exit with error"


@pytest.fixture
def client():
    """Create client to test flask application."""
    flask_app.config.update({"TESTING": True})

    with flask_app.test_client() as client:
        yield client


def test_home_page(client):
    """Test flask home.html."""
    resp = client.get("/")
    assert resp.status_code == 200


def test_stakeholder_page(client):
    """Test flask home_stakeholder.html."""
    resp = client.get("/stakeholder")
    assert resp.status_code == 200
