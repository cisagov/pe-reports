"""File to be used to create test for pe-reports."""

# Standard Python Libraries
import sys
import unittest
from unittest.mock import patch

# Third-Party Libraries
import pytest

# cisagov Libraries
import pe_reports.report_generator

PROJECT_VERSION = pe_reports.__version__

# TODO: Replace current dummy test with useful tests - https://github.com/cisagov/pe-reports/issues/3#issue-909531010


def test_output(capsys):
    """Testing captured output."""
    print("hello")
    sys.stderr.write("world\n")
    captured = capsys.readouterr()
    assert captured.out == "hello\n"
    assert captured.err == "world\n"
    print("next")
    captured = capsys.readouterr()
    assert captured.out == "next\n"


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


class TestingStringMethods(unittest.TestCase):
    """Simple test for first-commit only."""

    def test_string_equality(self):
        """Calculates the string output."""
        # if both arguments are equal then it's success
        self.assertEqual("ttp" * 5, "ttpttpttpttpttp")

    def test_string_case(self):
        """Compare two strings."""
        # if both arguments are equal then it's success
        self.assertEqual("tutorialspoint".upper(), "TUTORIALSPOINT")

    def test_is_string_upper(self):
        """Checks whether a string is upper or not."""
        # used to check whether the statement is True or False
        # the result of expression inside the **assertTrue** must be True to pass the test case
        # the result of expression inside the **assertFalse** must be False to pass the test case
        self.assertTrue("TUTORIALSPOINT".isupper())
        self.assertFalse("TUTORIALSpoint".isupper())


if __name__ == "__main__":
    """Runs the simple test."""
    unittest.main()
