"""Generate metrics for pe-reports."""
# Standard Python Libraries
# from datetime import datetime
# import logging

# Third-Party Libraries
# import numpy as np
# import pandas as pd
# from .query_db import query_hibp_view, query_cyberSix_creds

# Break up running metrics into functions.
# Document String each metric output to its report title.
# Remove postgress connect/close from each metric function.

# TODO: Create scripts to build charting metrics; credentials
# Issue: https://github.com/cisagov/pe-reports/issues/78


class Credentials:
    """Credentials class."""

    def __init__(self, start_date, end_date, org_uid):
        """Initialize credentials class."""
        self.start_date = start_date
        self.end_date = end_date
        self.org_uid = org_uid

    def total(self):
        """Total credentials exposed."""
        return  # creds

    def password(self):
        """Credentials with password."""
        return  # pw_creds

    def breaches(self):
        """Distinct breaches."""
        return  # breach

    def by_day(self):
        """Credentials exposed by day."""
        return  # ce_date_df

    def breach_details(self):
        """Breach details."""
        return  # breach_det_df
