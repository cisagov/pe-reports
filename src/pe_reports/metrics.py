"""Class methods for report metrics."""

# cisagov Libraries
from pe_reports.data.db_query import query_cyberSix_creds, query_hibp_view


class Credentials:
    """Credentials class."""

    def __init__(self, start_date, end_date, org_uid):
        """Initialize credentials class."""
        self.start_date = start_date
        self.end_date = end_date
        self.org_uid = org_uid
        self.query_cyberSix_creds = query_cyberSix_creds(org_uid, start_date, end_date)
        self.query_hibp_view = query_hibp_view(org_uid, start_date, end_date)

    def total(self):
        """Return total number of credentials."""
        df_cred_csg = self.query_cyberSix_creds.shape[0]
        df_cred_hibp = self.query_hibp_view.shape[0]
        total = df_cred_csg + df_cred_hibp
        return total

    # TODO the following functions correspond to functions at report_generator.py
    # TODO and will be added in follow up PR's.
    def password(self):
        """Return total number of credentials with passwords."""

    def breached(self):
        """Return total number of breached credentials."""

    def by_days(self):
        """Return number of credentials by day."""

    def breach_details(self):
        """Return breach details."""
