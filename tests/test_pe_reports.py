"""File to be used to create test for pe-reports."""

# Standard Python Libraries
import unittest

# TODO: Replace current dummy test with useful tests - https://github.com/cisagov/pe-reports/issues/3#issue-909531010


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
