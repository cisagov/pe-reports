"""File to be used to create test for pe-reports."""

# Standard Python Libraries
import logging
import sys
from unittest.mock import patch

# Third-Party Libraries
import pandas as pd
import pytest

# cisagov Libraries
from pe_reports import CENTRAL_LOGGING_FILE
from pe_reports import app as flask_app
import pe_reports.data.db_query
from pe_reports.report_gen.views import validate_date, validate_filename
import pe_reports.report_generator

log_levels = (
    "debug",
    "info",
    "warning",
    "error",
    "critical",
)

# TODO: Setup log rotate to rotate pe-reports log file
#  Issue - https://github.com/cisagov/pe-reports/issues/248

# Setup logging to file
logging.basicConfig(
    filename=CENTRAL_LOGGING_FILE,
    filemode="a",
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    datefmt="%m/%d/%Y %I:%M:%S",
    level="INFO",
)


PROJECT_VERSION = pe_reports.__version__


# TODO: Replace current dummy test with useful tests
#  Issue - https://github.com/cisagov/pe-reports/issues/3#issue-909531010


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


# TODO: Test data cleanup in metrics for each source
# Issue - https://github.com/cisagov/pe-reports/issues/264


@pytest.fixture
def client():
    """Create client to test flask application."""
    flask_app.config.update({"TESTING": True})

    with flask_app.test_client() as client:
        yield client


# TODO: Increase flask UI testing to test Cyber Six Gill API responses. The
#   current state of the CSG API times out randomly.
#   See https://github.com/cisagov/pe-reports/issues/213
def test_home_page(client):
    """Test flask home.html is available and verify a string on the page."""
    resp = client.get("/")
    assert resp.status_code == 200
    assert b"Home" in resp.data


def test_stakeholder_page(client):
    """Test flask home_stakeholder.html is available and verify a string on the page."""
    resp = client.get("/stakeholder")
    assert resp.status_code == 200
    assert b"Stakeholder" in resp.data


@patch.object(pe_reports.report_generator, "upload_file_to_s3")
@patch.object(pe_reports.report_generator, "embed")
@patch.object(pe_reports.report_generator, "init")
@patch.object(pe_reports.report_generator, "get_orgs")
@patch.object(pe_reports.report_generator, "connect")
def test_report_generator(
    mock_db_connect, mock_get_orgs, mock_init, mock_embed, mock_s3_upload
):
    """Test report is generated."""
    mock_db_connect.return_value = "connection"
    mock_get_orgs.return_value = [("pe_org_uid", "Test Org", "TestOrg")]
    source_html = ""
    creds_sum = ""
    creds_sum = pd.DataFrame()
    masq_df = pd.DataFrame()
    insecure_df = pd.DataFrame()
    vulns_df = pd.DataFrame()
    assets_df = pd.DataFrame()
    dark_web_mentions = pd.DataFrame()
    alerts = pd.DataFrame()
    top_cves = pd.Series(dtype="object")
    mock_init.return_value = (
        source_html,
        creds_sum,
        masq_df,
        insecure_df,
        vulns_df,
        assets_df,
        dark_web_mentions,
        alerts,
        top_cves,
    )
    mock_embed.return_value = (
        10000000,
        False,
        "output/TestOrg/Posture_and_Exposure_Report-TestOrg-2022-09-30.pdf",
    )

    return_value = pe_reports.report_generator.generate_reports("2022-09-30", "output")
    mock_s3_upload.assert_called_once_with(
        "output/TestOrg/Posture_and_Exposure_Report-TestOrg-2022-09-30.pdf",
        "2022-09-30",
        None,
    )
    assert return_value == 1


def test_report_gen_page(client):
    """Test flask report_gen.html is available and verify a string on the page."""
    resp = client.get("/report_gen")
    assert resp.status_code == 200
    assert b"Generate Cybersixgill Bulletin" in resp.data


@pytest.mark.parametrize(
    "filename, expected_result",
    [
        ("#superfile", False),
        ("Re@lfile", False),
        ("File+100", False),
        ("<filename>", False),
        ("{filename", False),
        ("awesome_file!!", False),
        ("File$name", False),
        ("File/name", False),
        ("file name", False),
        ("", False),
        ("valid_file", True),
    ],
)
def test_valid_filename(filename, expected_result):
    """Test valid filename."""
    assert validate_filename(filename) == expected_result


@pytest.mark.parametrize(
    "date, expected_result",
    [
        ("22-12-22", False),
        ("2022/03/15", False),
        ("2020-12-30", False),
        ("2020-2-27", False),
        ("2015-11-31", False),
        ("2020-02-28", False),
        ("2020-02-29", True),
        ("2020-11-30", True),
        ("2020-12-31", True),
        ("2020-12-15", True),
    ],
)
def test_valid_date(date, expected_result):
    """Test valid date."""
    assert validate_date(date) == expected_result
