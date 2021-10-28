"""Class methods for report metrics."""

# TODO: Merge PR 91 and PR 92 to test
# from .query_db import query_hibp_view, query_cyberSix_creds


class Credentials:
    """Credentials class."""

    def __init__(self, start_date, end_date, org_uid):
        """Initialize credentials class."""
        self.start_date = start_date
        self.end_date = end_date
        self.org_uid = org_uid

    def total(self, query_hibp_view, query_cyberSix_creds):
        """Return total number of credentials."""
        total_creds = query_hibp_view.count()
        total_creds_cyber = query_cyberSix_creds.count()
        creds = total_creds + total_creds_cyber
        return creds

    def password(self, query_hibp_view, query_cyberSix_creds):
        """Password credentials."""
        password_creds = query_hibp_view.filter(
            query_hibp_view.password_type == "password"
        ).count()
        password_creds_cyber = query_cyberSix_creds.filter(
            query_cyberSix_creds.password_type == "password"
        ).count()
        password_creds = password_creds + password_creds_cyber
        return password_creds

    def breaches(self, query_hibp_view):
        """Breaches."""
        breaches = query_hibp_view.filter(
            query_hibp_view.password_type == "breach"
        ).count()
        return breaches

    def by_day(self, query_hibp_view, query_cyberSix_creds):
        """By day."""
        by_day = (
            query_hibp_view.filter(query_hibp_view.password_type == "password")
            .group_by(query_hibp_view.date_added)
            .count()
        )
        by_day_cyber = (
            query_cyberSix_creds.filter(
                query_cyberSix_creds.password_type == "password"
            )
            .group_by(query_cyberSix_creds.date_added)
            .count()
        )
        by_day = by_day + by_day_cyber
        return by_day

    def breach_details(self, query_hibp_view):
        """Breach details."""
        breach_details = (
            query_hibp_view.filter(query_hibp_view.password_type == "breach")
            .group_by(query_hibp_view.breach_name)
            .count()
        )
        return breach_details
