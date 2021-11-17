"""Class methods for report metrics."""

# Third-Party Libraries
import numpy as np
import pandas as pd

# cisagov Libraries
from pe_reports.data.db_query import query_cyberSix_creds, query_hibp_view


class Credentials:
    """Credentials class."""

    def __init__(self, start_date, end_date, org_uid):
        """Initialize credentials class."""
        self.start_date = start_date
        self.end_date = end_date
        self.org_uid = org_uid
        c6 = query_cyberSix_creds(org_uid, start_date, end_date)
        c6.loc[c6["breach_name"] == "", "breach_name"] = "Cyber_six_" + pd.to_datetime(
            c6["breach_date"]
        ).dt.strftime("%m/%d/%Y")
        c6["description"] = (
            c6["description"].str.split("Query to find the related").str[0]
        )
        c6["password_included"] = np.where(c6["password"] != "", True, False)
        self.query_cyberSix_creds = c6
        self.query_hibp_view = query_hibp_view(org_uid, start_date, end_date)

    def total(self):
        """Return total number of credentials."""
        df_cred_csg = self.query_cyberSix_creds.shape[0]
        df_cred_hibp = self.query_hibp_view.shape[0]
        total = df_cred_csg + df_cred_hibp
        return total

    def password(self):
        """Return total number of credentials with passwords."""
        pw_creds_csg = len(
            self.query_cyberSix_creds[self.query_cyberSix_creds["password_included"]]
        )
        pw_creds_hibp = len(
            self.query_hibp_view[self.query_hibp_view["password_included"]]
        )
        password = pw_creds_csg + pw_creds_hibp
        return password

    def breaches(self):
        """Return total number of breaches."""
        all_breaches = pd.concat(
            self.query_hibp_view["breach_name"],
            self.query_cyberSix_creds["breach_name"],
        )
        breaches = all_breaches.nunique()
        return breaches

    def by_days(self):
        """Return number of credentials by day."""
        hibp_df = self.query_hibp_view
        c6_df = self.query_cyberSix_creds
        c6_df_2 = c6_df[["create_time", "password_included", "email"]]
        c6_df_2 = c6_df_2.rename(columns={"create_time": "modified_date"})

        hibp_df = hibp_df[["modified_date", "password_included", "email"]]
        hibp_df = hibp_df.append(c6_df_2, ignore_index=True)
        hibp_df["modified_date"] = pd.to_datetime(hibp_df["modified_date"]).dt.date

        hibp_df = hibp_df.groupby(
            ["modified_date", "password_included"], as_index=False
        ).agg({"email": ["count"]})
        idx = pd.date_range(self.start_date, self.end_date)
        hibp_df.columns = hibp_df.columns.droplevel(1)
        hibp_df = (
            hibp_df.pivot(
                index="modified_date", columns="password_included", values="email"
            )
            .fillna(0)
            .reset_index()
            .rename_axis(None)
        )
        hibp_df.columns.name = None
        hibp_df = (
            hibp_df.set_index("modified_date")
            .reindex(idx)
            .fillna(0.0)
            .rename_axis("added_date")
        )
        hibp_df["modified_date"] = hibp_df.index
        hibp_df["modified_date"] = hibp_df["modified_date"].dt.strftime("%m/%d/%y")
        hibp_df = hibp_df.set_index("modified_date")

        ce_date_df = hibp_df.rename(
            columns={True: "Passwords Included", False: "No Password"}
        )
        if len(ce_date_df.columns) == 0:
            ce_date_df["Passwords Included"] = 0
        return ce_date_df

    def breach_details(self):
        """Return breach details."""
        hibp_df = self.query_hibp_view
        c6_df = self.query_cyberSix_creds
        c6_df_2 = c6_df[
            [
                "breach_name",
                "create_time",
                "description",
                "breach_date",
                "password_included",
                "email",
            ]
        ]
        c6_df_2 = c6_df_2.rename(columns={"create_time": "modified_date"})
        view_df_2 = hibp_df[
            [
                "breach_name",
                "modified_date",
                "description",
                "breach_date",
                "password_included",
                "email",
            ]
        ]
        view_df_2 = view_df_2.append(c6_df_2, ignore_index=True)

        breach_df = view_df_2.groupby(
            [
                "breach_name",
                "modified_date",
                "description",
                "breach_date",
                "password_included",
            ],
            as_index=False,
        ).agg({"email": ["count"]})

        breach_df.columns = breach_df.columns.droplevel(1)
        breach_df = breach_df.rename(columns={"email": "number_of_creds"})
        breach_df = breach_df[
            [
                "breach_name",
                "breach_date",
                "modified_date",
                "password_included",
                "number_of_creds",
            ]
        ]
        breach_det_df = breach_df.rename(columns={"modified_date": "update_date"})

        if len(breach_det_df) > 0:
            breach_det_df["update_date"] = breach_det_df["update_date"].dt.strftime(
                "%m/%d/%y"
            )
            breach_det_df["breach_date"] = pd.to_datetime(
                breach_det_df["breach_date"]
            ).dt.strftime("%m/%d/%y")

        breach_det_df = breach_det_df.rename(
            columns={
                "breach_name": "Breach Name",
                "breach_date": "Breach Date",
                "update_date": "Date Reported",
                "password_included": "Password Included",
                "number_of_creds": "Number of Creds",
            }
        )
        return breach_det_df

    def breach_appendix(self):
        """Return breach name and description to be added to the appendix."""
        hibp_df = self.query_hibp_view
        c6_df = self.query_cyberSix_creds
        c6_df_2 = c6_df[["breach_name", "description"]]
        c6_df_2 = c6_df_2.rename(columns={"create_time": "modified_date"})
        view_df_2 = hibp_df[["breach_name", "description"]]
        view_df_2 = view_df_2.append(c6_df_2, ignore_index=True)

        view_df_2.drop_duplicates()
        breach_appendix = view_df_2[["breach_name", "description"]]
        return breach_appendix
