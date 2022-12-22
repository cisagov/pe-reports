"""Tests for the pe-source module."""

# Standard Python Libraries
import logging
import sys
from unittest.mock import patch

# Third-Party Libraries
import pandas as pd
import pytest

# cisagov Libraries
from pe_reports import CENTRAL_LOGGING_FILE
import pe_source.cybersixgill
import pe_source.data.sixgill.api
import pe_source.dnstwistscript
import pe_source.pe_scripts
import pe_source.shodan

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
            "shodan",
            f"--log-level={level}",
        ],
    ):
        with patch.object(logging.root, "handlers", []):
            with patch.object(pe_source.shodan.Shodan, "run_shodan"):
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
                    logging.getLevelName(logging.root.getEffectiveLevel())
                    == level.upper()
                ), f"root logger level should be set to {level.upper()}"
                assert return_code is None, "main() should return success"


def test_source_bad_log_level():
    """Validate bad log-level argument returns error."""
    with patch.object(
        sys,
        "argv",
        [
            "pe-source",
            "shodan",
            "--log-level=emergency",
        ],
    ):
        return_code = None
        try:
            pe_source.pe_scripts.main()
        except SystemExit as sys_exit:
            return_code = sys_exit.code
        assert return_code == 1, "main() should exit with error"


# Test source argument
def test_source_is_cybersixgill():
    """Validate source argument runs Cybersixgill."""
    with patch.object(
        sys,
        "argv",
        [
            "pe-source",
            "cybersixgill",
        ],
    ):
        with patch.object(
            pe_source.cybersixgill.Cybersixgill, "run_cybersixgill"
        ) as mock_sixgill:
            with patch.object(pe_source.shodan.Shodan, "run_shodan") as mock_shodan:
                pe_source.pe_scripts.main()
                mock_sixgill.assert_called_with(), "cybersixgill should be called"
                mock_shodan.assert_not_called(), "shodan should not be called"


def test_source_is_shodan():
    """Validate source argument runs Shodan."""
    with patch.object(
        sys,
        "argv",
        [
            "pe-source",
            "shodan",
        ],
    ):
        with patch.object(
            pe_source.cybersixgill.Cybersixgill, "run_cybersixgill"
        ) as mock_sixgill:
            with patch.object(pe_source.shodan.Shodan, "run_shodan") as mock_shodan:
                pe_source.pe_scripts.main()
                mock_shodan.assert_called_with(), "shodan should be called"
                mock_sixgill.assert_not_called(), "cybersixgill should not be called"


def test_bad_source():
    """Validate bad source argument returns error."""
    with patch.object(
        sys,
        "argv",
        [
            "pe-source",
            "bad_source",
        ],
    ):
        return_code = None
        try:
            pe_source.pe_scripts.main()
        except SystemExit as sys_exit:
            return_code = sys_exit.code
        assert return_code == 1, "should exit with error"


# Cybersixgill
@patch.object(pe_source.cybersixgill.Cybersixgill, "get_topCVEs")
@patch.object(pe_source.cybersixgill.Cybersixgill, "get_credentials")
@patch.object(pe_source.cybersixgill.Cybersixgill, "get_mentions")
@patch.object(pe_source.cybersixgill.Cybersixgill, "get_alerts")
@patch("pe_source.cybersixgill.get_data_source_uid")
@patch("pe_source.cybersixgill.get_sixgill_organizations")
@patch("pe_source.cybersixgill.get_orgs")
def test_cybersix_methods_all(
    mock_get_orgs,
    mock_get_sixgill_orgs,
    mock_get_source_id,
    mock_sixgill_alerts,
    mock_sixgill_mentions,
    mock_sixgill_credentials,
    mock_sixgill_topCVEs,
):
    """Validate all Cybersixgill methods are called correctly."""
    with patch.object(sys, "argv", ["pe-source", "cybersixgill"]):
        mock_get_orgs.return_value = [
            {"org_uid": "pe_org_uid", "org_name": "Test Org", "cyhy_db_name": "TestOrg"}
        ]
        mock_get_sixgill_orgs.return_value = {
            "TestOrg": [
                "role",
                "user",
                "customer",
                "image",
                [],
                "sixgill_org_id",
            ]
        }
        mock_get_source_id.return_value = "source_uid"
        pe_source.pe_scripts.main()
        mock_sixgill_alerts.assert_called_with(
            "TestOrg", "sixgill_org_id", "pe_org_uid", "source_uid"
        )
        mock_sixgill_mentions.assert_called_with(
            "TestOrg", "sixgill_org_id", "pe_org_uid", "source_uid"
        )
        mock_sixgill_credentials.assert_called_with(
            "TestOrg", "sixgill_org_id", "pe_org_uid", "source_uid"
        )
        mock_sixgill_topCVEs.assert_called_with("source_uid")


@patch.object(pe_source.cybersixgill.Cybersixgill, "get_alerts")
@patch("pe_source.cybersixgill.get_data_source_uid")
@patch("pe_source.cybersixgill.get_sixgill_organizations")
@patch("pe_source.cybersixgill.get_orgs")
def test_cybersix_methods_alerts(
    mock_get_orgs,
    mock_get_sixgill_orgs,
    mock_get_source_id,
    mock_sixgill_alerts,
):
    """Validate only the Cybersixgill alert method is called."""
    with patch.object(
        sys, "argv", ["pe-source", "cybersixgill", "--cybersix-methods=alerts"]
    ):
        mock_get_orgs.return_value = [
            {"org_uid": "pe_org_uid", "org_name": "Test Org", "cyhy_db_name": "TestOrg"}
        ]
        mock_get_sixgill_orgs.return_value = {
            "TestOrg": [
                "role",
                "user",
                "customer",
                "image",
                [],
                "sixgill_org_id",
            ]
        }
        mock_get_source_id.return_value = "source_uid"
        pe_source.pe_scripts.main()
        mock_sixgill_alerts.assert_called_with(
            "TestOrg", "sixgill_org_id", "pe_org_uid", "source_uid"
        )


# Test Credentials
@patch("pe_source.cybersixgill.insert_sixgill_credentials")
@patch("pe_source.cybersixgill.get_breaches")
@patch("pe_source.cybersixgill.insert_sixgill_breaches")
@patch("pe_source.cybersixgill.creds")
@patch("pe_source.cybersixgill.root_domains")
def test_cybersix_credentials(
    mock_root_domains,
    mock_creds_df,
    mock_insert_breaches,
    mock_breaches,
    mock_insert_creds,
):
    """Validate credential breach data is parsed and cleaned correctly."""
    mock_root_domains.return_value = ["sample.com"]
    # Mock credentials from cybersixgill
    mock_creds_df.return_value = pd.read_json("tests/data/cybersix_creds.json")
    mock_breaches.return_value = [
        ("Cybersixgill_1", "breach_uid_1"),
        ("Breach 2", "breach_uid_2"),
        ("Breach 3", "breach_uid_3"),
        ("Breach 4", "breach_uid_4"),
        ("Breach 5", "breach_uid_5"),
        ("Breach 5", "breach_uid_5"),
        ("Breach 6", "breach_uid_6"),
    ]

    result = pe_source.cybersixgill.Cybersixgill(
        ["TestOrg"], ["credentials"]
    ).get_credentials("org_id", "sixgill_org_id", "pe_org_uid", "source_uid")

    # Assert insert breaches function is called with the correct data
    breach_insert_df = pd.read_json("tests/data/cybersix_breach_insert.json")
    pd.testing.assert_frame_equal(
        mock_insert_breaches.call_args[0][0].sort_index(axis=1),
        breach_insert_df.sort_index(axis=1),
    )
    # Assert insert credentials function is called with the correct data
    creds_insert_df = pd.read_json("tests/data/cybersix_creds_insert.json")
    pd.testing.assert_frame_equal(
        mock_insert_creds.call_args[0][0].sort_index(axis=1),
        creds_insert_df.sort_index(axis=1),
    )
    # Assert function completes without errors
    assert result == 0


# Test Shodan
@patch("pe_source.shodan.run_shodan_thread")
@patch("pe_source.shodan.shodan_api_init")
@patch("pe_source.shodan.get_orgs")
def test_shodan_search(
    mock_get_orgs,
    mock_shodan_api,
    mock_shodan_thread,
):
    """Validate Shodan search is called."""
    with patch.object(sys, "argv", ["pe-source", "shodan"]):
        mock_get_orgs.return_value = [
            {"org_uid": "pe_org_uid", "org_name": "Test Org", "cyhy_db_name": "TestOrg"}
        ]
        mock_shodan_api.return_value = ["api-key-1"]
        pe_source.pe_scripts.main()
        mock_shodan_thread.assert_called_with(
            "api-key-1",
            [
                {
                    "org_uid": "pe_org_uid",
                    "org_name": "Test Org",
                    "cyhy_db_name": "TestOrg",
                }
            ],
            "Thread 1:",
        )


def test_dnstwistfuzzing():
    """Test if dnstwist is installed correctly."""
    res = pe_source.dnstwistscript.execute_dnstwist("a.com", test=1)
    assert len(res) != 0
    assert res[1]["fuzzer"] == "addition"
    assert res[1]["domain"] != ""
    assert (
        len(res[1]["dns_ns"]) != 0
    )  # all domains returned should be registered so this must have something


def test_blocklist():
    """Test if blocklist is working correctly."""
    dom = {
        "fuzzer": "addition",
        "domain": "a0.com",
        "dns_ns": ["liz.ns.cloudflare.com"],
        "dns_a": ["104.21.34.160"],
        "dns_aaaa": ["2606:4700:3036::6815:22a0"],
        "dns_mx": ["alt1.aspmx.l.google.com"],
        "ssdeep_score": "",
    }
    test1, test2 = pe_source.dnstwistscript.checkBlocklist(dom, 1, 1, 1, [])
    assert test1["data_source_uid"] == 1
    assert test1["domain_permutation"] == "a0.com"
    assert test2[0] == "a0.com"


# TODO: Add shodan search once this issue is addressed
# Issue - https://github.com/cisagov/pe-reports/issues/171
