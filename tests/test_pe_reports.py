"""This module contains the tests for the report_generator test."""

import unittest
import os
import sys
import shutil
import subprocess

sys.path.append("../src")


class Test(unittest.TestCase):
    """The tests for the report_generator tool."""

    def test_agency(self):
        """Test the tool on a single agency."""
        datestring = "2020-06-01"
        _id = "agency"
        cwd = os.getcwd()
        output_directory = f"{cwd}/temp_{datestring}_{_id}"

        # Create output directory
        subprocess.call(["mkdir", output_directory])
        print("[INFO]: ", output_directory)

        # Delete output directory
        try:
            shutil.rmtree(output_directory)
            print("Temporary output directory and files successfully deleted")
        except OSError as e:
            print("Error: %s : %s" % (output_directory, e.strerror))


if __name__ == "__main__":
    unittest.main()
