"""Class methods for report metrics."""

# Import query functions
# Standard Python Libraries
import calendar
import datetime

# New Imports
from datetime import timedelta

# Third-Party Libraries
from dateutil.relativedelta import relativedelta
import pandas as pd

from .data.db_query import (
    query_breachdetails_view,
    query_creds_view,
    query_credsbyday_view,
    query_darkweb,
    query_darkweb_cves,
    query_domMasq,
    query_domMasq_alerts,
    query_shodan,
    get_org_first_report_date,  # Dark Web Usage, WIP
)
from .data.translator import translate


# ---------- v Helper Functions v ------------


def checkEmptyTable(df):
    """Adds note explaining no new data was found for this report period if dataframe is empty"""
    if len(df) == 0:
        noDataRow = ["..."] * len(df.columns)
        noDataRow[0] = "No New Data"
        df.loc[len(df)] = noDataRow


def percentChange(initial, final):
    """Calculates the percentage change between initial and final values"""
    if initial == 0 and final == 0:
        return 0.00
    elif initial == 0 and final != 0:
        return "New Value"
    else:
        return round((float(final - initial) / float(initial)) * 100, 2)


def percentChangeStr(percChng):
    """Creates string that displays metric and percent change in value"""
    finalString = ""
    if percChng == "New Value":
        finalString = "(\u2191 Up From Zero)"
    elif percChng < 0:
        finalString = "(\u2193 %.2f%%)" % (percChng)
    elif percChng > 0:
        finalString = "(\u2191 +%.2f%%)" % (percChng)
    else:
        finalString = "(No Change)"
    return finalString


def truncColumn(df, column, numChar):
    """Takes in a dataframe and truncates a column to the specified character limit"""
    df[column] = df[column].str.slice(0, numChar) + " ..."


def getPrevPeriod(currReportDate):
    """Calculates the start/end dates of the previous report period"""
    # Calculate start date of current report period
    if currReportDate.day == 15:
        currStart = datetime.datetime(currReportDate.year, currReportDate.month, 1)
    else:
        currStart = datetime.datetime(currReportDate.year, currReportDate.month, 16)
    # Calculate start/end dates for previous report period
    prevEnd = currStart - timedelta(days=1)
    if prevEnd.day == 15:
        prevStart = datetime.datetime(prevEnd.year, prevEnd.month, 1)
    else:
        prevStart = datetime.datetime(prevEnd.year, prevEnd.month, 16)
    return [prevStart, prevEnd]


def prevSixPeriods(currDate):
    """Returns the start/end dates of the previous four report periods"""
    if currDate.day == 15:
        # Calculate start/end dates for previous report periods 1-6
        p1_start = (currDate + relativedelta(months=-3)).replace(day=16)
        p1_end = currDate + relativedelta(months=-3)
        p1_end = p1_end.replace(day=calendar.monthrange(p1_end.year, p1_end.month)[1])

        p2_start = (currDate + relativedelta(months=-2)).replace(day=1)
        p2_end = currDate + relativedelta(months=-2)

        p3_start = (currDate + relativedelta(months=-2)).replace(day=16)
        p3_end = currDate + relativedelta(months=-2)
        p3_end = p3_end.replace(day=calendar.monthrange(p3_end.year, p3_end.month)[1])

        p4_start = (currDate + relativedelta(months=-1)).replace(day=1)
        p4_end = currDate + relativedelta(months=-1)

        p5_start = (currDate + relativedelta(months=-1)).replace(day=16)
        p5_end = currDate + relativedelta(months=-1)
        p5_end = p5_end.replace(day=calendar.monthrange(p5_end.year, p5_end.month)[1])

        p6_start = currDate.replace(day=1)
        p6_end = currDate
    else:
        # Calculate start/end dates for previous report periods 1-6
        p1_start = (currDate + relativedelta(months=-2)).replace(day=1)
        p1_end = (currDate + relativedelta(months=-2)).replace(day=15)

        p2_start = (currDate + relativedelta(months=-2)).replace(day=16)
        p2_end = currDate + relativedelta(months=-2)
        p2_end = p2_end.replace(day=calendar.monthrange(p2_end.year, p2_end.month)[1])

        p3_start = (currDate + relativedelta(months=-1)).replace(day=1)
        p3_end = (currDate + relativedelta(months=-1)).replace(day=15)

        p4_start = (currDate + relativedelta(months=-1)).replace(day=16)
        p4_end = currDate + relativedelta(months=-1)
        p4_end = p4_end.replace(day=calendar.monthrange(p4_end.year, p4_end.month)[1])

        p5_start = currDate.replace(day=1)
        p5_end = currDate.replace(day=15)

        p6_start = currDate.replace(day=16)
        p6_end = currDate
    return [
        p1_start,
        p1_end,
        p2_start,
        p2_end,
        p3_start,
        p3_end,
        p4_start,
        p4_end,
        p5_start,
        p5_end,
        p6_start,
        p6_end,
    ]


class Credentials:
    """Credentials class."""

    def __init__(self, trending_start_date, start_date, end_date, org_uid):
        """Initialize credentials class."""
        self.trending_start_date = trending_start_date
        self.start_date = start_date
        self.end_date = end_date
        self.org_uid = org_uid
        self.trending_creds_view = query_creds_view(
            org_uid, trending_start_date, end_date
        )
        self.creds_view = query_creds_view(org_uid, start_date, end_date)
        self.creds_by_day = query_credsbyday_view(
            org_uid, trending_start_date, end_date
        )
        self.breach_details_view = query_breachdetails_view(
            org_uid, start_date, end_date
        )

    def by_days(self):
        """Return number of credentials by day."""
        df = self.creds_by_day
        df = df[["mod_date", "no_password", "password_included"]].copy()

        # Calculate start/stop dates of previous 6 periods
        [
            p1_start,
            p1_end,
            p2_start,
            p2_end,
            p3_start,
            p3_end,
            p4_start,
            p4_end,
            p5_start,
            p5_end,
            p6_start,
            p6_end,
        ] = prevSixPeriods(self.end_date)

        # Group credential counts by report period
        period1 = df.loc[((df["mod_date"] >= p1_start) & (df["mod_date"] <= p1_end))]
        period2 = df.loc[((df["mod_date"] >= p2_start) & (df["mod_date"] <= p2_end))]
        period3 = df.loc[((df["mod_date"] >= p3_start) & (df["mod_date"] <= p3_end))]
        period4 = df.loc[((df["mod_date"] >= p4_start) & (df["mod_date"] <= p4_end))]
        period5 = df.loc[((df["mod_date"] >= p5_start) & (df["mod_date"] <= p5_end))]
        period6 = df.loc[((df["mod_date"] >= p6_start) & (df["mod_date"] <= p6_end))]

        # Aggregate each report period into a single row
        df2 = pd.concat(
            (
                period1[["no_password", "password_included"]].sum().to_frame().T,
                period2[["no_password", "password_included"]].sum().to_frame().T,
                period3[["no_password", "password_included"]].sum().to_frame().T,
                period4[["no_password", "password_included"]].sum().to_frame().T,
                period5[["no_password", "password_included"]].sum().to_frame().T,
                period6[["no_password", "password_included"]].sum().to_frame().T,
            ),
            ignore_index=True,
        )
        df2["modified_date"] = [p1_end, p2_end, p3_end, p4_end, p5_end, p6_end]
        df2["modified_date"] = pd.to_datetime(df2["modified_date"], utc=True)
        df2["modified_date"] = df2["modified_date"].dt.strftime("%b %d")
        df2 = df2.set_index("modified_date")
        df2 = df2.astype({"password_included": float, "no_password": float})
        df2 = df2.rename(
            columns={
                "password_included": "Passwords Included",
                "no_password": "No Password",
            }
        )

        if len(df2.columns) == 0:
            df2["Passwords Included"] = 0
        return df2

    def breaches(self):
        """Return total number of breaches."""
        all_breaches = self.creds_view["breach_name"]
        return all_breaches.nunique()

    def breach_appendix(self):
        """Return breach name and description to be added to the appendix."""
        view_df = self.creds_view
        view_df = view_df[["breach_name", "description"]]

        view_df = view_df.drop_duplicates()
        return view_df[["breach_name", "description"]]

    def breach_details(self):
        """Return breach details."""
        breach_df = self.breach_details_view
        breach_det_df = breach_df.rename(columns={"modified_date": "update_date"})
        breach_det_df["update_date"] = pd.to_datetime(breach_det_df["update_date"])
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

        # ----- DAYS UNREPORTED METRIC WIP ----- v
        # breach_det_df.insert(loc=3, column="Days Unreported", value="")
        # if len(breach_det_df) > 0:
        #    breach_det_df["Days Unreported"] = (
        #        pd.to_datetime(breach_det_df["Date Reported"])
        #        - pd.to_datetime(breach_det_df["Breach Date"])
        #    ).dt.days
        # ----- DAYS UNREPORTED METRIC WIP ---- ^

        # Empty table check:
        checkEmptyTable(breach_det_df)

        return breach_det_df

    def password(self):
        """Return total number of credentials with passwords."""
        pw_creds = len(self.creds_view[self.creds_view["password_included"]])
        return pw_creds

    def total(self):
        """Return total number of credentials found in breaches."""
        df_cred = self.creds_view.shape[0]
        return df_cred

    def perChngCred(self, option):
        "Consolidated percent change function for the credential pub & abuse page metrics"
        [prevStart, prevEnd] = getPrevPeriod(self.end_date)
        prev_creds_view = query_creds_view(self.org_uid, prevStart, prevEnd)
        [currTotal, prevTotal] = [1, 1]
        if option == "total":
            prevTotal = prev_creds_view.shape[0]
            currTotal = self.creds_view.shape[0]
        elif option == "pass":
            prevTotal = prev_creds_view[prev_creds_view["password_included"]].shape[0]
            currTotal = self.creds_view[self.creds_view["password_included"]].shape[0]
        elif option == "breach":
            prevTotal = prev_creds_view["breach_name"].nunique()
            currTotal = self.creds_view["breach_name"].nunique()
        return percentChangeStr(percentChange(prevTotal, currTotal))


class Domains_Masqs:
    """Domains Masquerading class."""

    def __init__(self, start_date, end_date, org_uid):
        """Initialize domains masquerading class."""
        self.start_date = start_date
        self.end_date = end_date
        self.org_uid = org_uid
        df = query_domMasq(org_uid, start_date, end_date)
        self.df_mal = df[df["malicious"] == True]
        self.dom_alerts_df = query_domMasq_alerts(org_uid, start_date, end_date)

    def count(self):
        """Return total count of malicious domains."""
        df = self.df_mal
        return len(df.index)

    def summary(self):
        """Return domain masquerading summary information."""
        if len(self.df_mal) > 0:
            domain_sum = self.df_mal[
                [
                    "domain_permutation",
                    "ipv4",
                    "ipv6",
                    "mail_server",
                    "name_server",
                ]
            ]
            domain_sum = domain_sum[:10]
            domain_sum.loc[domain_sum["ipv6"] == "", "ipv6"] = "NA"
            domain_sum = domain_sum.rename(
                columns={
                    "domain_permutation": "Domain",
                    "ipv4": "IPv4",
                    "ipv6": "IPv6",
                    "mail_server": "Mail Server",
                    "name_server": "Name Server",
                }
            )
        else:
            domain_sum = pd.DataFrame(
                columns=[
                    "Domain",
                    "IPv4",
                    "IPv6",
                    "Mail Server",
                    "Name Server",
                ]
            )

        # Empty table check:
        checkEmptyTable(domain_sum)

        return domain_sum

    def alert_count(self):
        """Return number of alerts."""
        dom_alert_count = len(self.dom_alerts_df)
        return dom_alert_count

    def alerts(self):
        """Return domain alerts."""
        dom_alerts_df = self.dom_alerts_df[["message", "date"]]
        dom_alerts_df = dom_alerts_df.rename(
            columns={"message": "Alert", "date": "Date"}
        )
        dom_alerts_df = dom_alerts_df[:10].reset_index(drop=True)

        # Empty table check:
        checkEmptyTable(dom_alerts_df)

        return dom_alerts_df

    def alerts_sum(self):
        """Return domain alerts summary."""
        dom_alerts_sum = self.dom_alerts_df[
            ["message", "date", "previous_value", "new_value"]
        ]
        return dom_alerts_sum

    def perChngDomain(self, option):
        "Consolidated percent change function for the domain alerts & masq page metrics"
        [prevStart, prevEnd] = getPrevPeriod(self.end_date)
        [currTotal, prevTotal] = [1, 1]
        if option == "suspect":
            prev_df = query_domMasq(self.org_uid, prevStart, prevEnd)
            prev_df_mal = prev_df[prev_df["malicious"] == True]
            prevTotal = len(prev_df_mal.index)
            currTotal = len(self.df_mal.index)
        elif option == "alerts":
            prev_dom_alerts_df = query_domMasq_alerts(self.org_uid, prevStart, prevEnd)
            prevTotal = len(prev_dom_alerts_df)
            currTotal = len(self.dom_alerts_df)
        return percentChangeStr(percentChange(prevTotal, currTotal))


class Malware_Vulns:
    """Malware and Vulnerabilities Class."""

    def __init__(self, start_date, end_date, org_uid):
        """Initialize Shodan vulns and malware class."""
        self.start_date = start_date
        self.end_date = end_date
        self.org_uid = org_uid
        insecure_df = query_shodan(
            org_uid,
            start_date,
            end_date,
            "vw_shodanvulns_suspected",
        )
        self.insecure_df = insecure_df

        vulns_df = query_shodan(
            org_uid, start_date, end_date, "vw_shodanvulns_verified"
        )
        vulns_df["port"] = vulns_df["port"].astype(str)
        self.vulns_df = vulns_df

        assets_df = query_shodan(org_uid, start_date, end_date, "shodan_assets")
        self.assets_df = assets_df

    @staticmethod
    def isolate_risky_assets(df):
        """Return risky assets from the insecure_df dataframe."""
        insecure = df[df["type"] == "Insecure Protocol"]
        insecure = insecure[
            (insecure["protocol"] != "http") & (insecure["protocol"] != "smtp")
        ]
        insecure["port"] = insecure["port"].astype(str)
        return insecure[["protocol", "ip", "port"]].drop_duplicates(keep="first")

    def insecure_protocols(self):
        """Get risky assets grouped by protocol."""
        risky_assets = self.isolate_risky_assets(self.insecure_df)
        risky_assets = (
            risky_assets.groupby("protocol")
            .agg(lambda x: "  ".join(set(x)))
            .reset_index()
        )
        if len(risky_assets.index) > 0:
            risky_assets["ip"] = risky_assets["ip"].str[:30]
            risky_assets.loc[risky_assets["ip"].str.len() == 30, "ip"] = (
                risky_assets["ip"] + "  ..."
            )

        # Empty table check:
        checkEmptyTable(risky_assets)

        return risky_assets

    def protocol_count(self):
        """Return a count for each insecure protocol."""
        risky_assets = self.isolate_risky_assets(self.insecure_df)
        # Horizontal bar: insecure protocol count
        pro_count = risky_assets.groupby(["protocol"], as_index=False)["protocol"].agg(
            {"id_count": "count"}
        )
        return pro_count

    def risky_ports_count(self):
        """Return total count of insecure protocols."""
        risky_assets = self.isolate_risky_assets(self.insecure_df)

        pro_count = risky_assets.groupby(["protocol"], as_index=False)["protocol"].agg(
            {"id_count": "count"}
        )

        # Total Open Ports with Insecure protocols
        return pro_count["id_count"].sum()

    def total_verif_vulns(self):
        """Return total count of verified vulns."""
        vulns_df = self.vulns_df
        verif_vulns = (
            vulns_df[["cve", "ip", "port"]]
            .groupby("cve")
            .agg(lambda x: "  ".join(set(x)))
            .reset_index()
        )

        if len(verif_vulns) > 0:
            verif_vulns["count"] = verif_vulns["ip"].str.split("  ").str.len()
            verifVulns = verif_vulns["count"].sum()

        else:
            verifVulns = 0

        return verifVulns

    @staticmethod
    def unverified_cve(df):
        """Subset insecure df to only potential vulnerabilities."""
        unverif_df = df[df["type"] != "Insecure Protocol"]
        unverif_df = unverif_df.copy()
        unverif_df["potential_vulns"] = (
            unverif_df["potential_vulns"].sort_values().apply(lambda x: sorted(x))
        )
        unverif_df["potential_vulns"] = unverif_df["potential_vulns"].astype("str")
        unverif_df = (
            unverif_df[["potential_vulns", "ip"]]
            .drop_duplicates(keep="first")
            .reset_index(drop=True)
        )
        unverif_df["potential_vulns_list"] = unverif_df["potential_vulns"].str.split(
            ","
        )
        unverif_df["count"] = unverif_df["potential_vulns_list"].str.len()
        return unverif_df

    def unverified_cve_count(self):
        """Return top 15 unverified CVEs and their counts."""
        unverif_df = self.unverified_cve(self.insecure_df)
        unverif_df = unverif_df[["ip", "count"]]
        unverif_df = unverif_df.sort_values(by=["count"], ascending=False)
        unverif_df = unverif_df[:15].reset_index(drop=True)
        return unverif_df

    def all_cves(self):
        """Get all verified and unverified CVEs."""
        unverif_df = self.unverified_cve(self.insecure_df)
        vulns_df = self.vulns_df
        verified_cves = vulns_df["cve"].tolist()
        all_cves = []
        for unverif_index, unverif_row in unverif_df.iterrows():
            for cve in unverif_row["potential_vulns_list"]:
                cve = cve.strip("[]' ")
                all_cves.append(cve)
        all_cves += verified_cves
        all_cves = list(set(all_cves))
        return all_cves

    def unverified_vuln_count(self):
        """Return the count of IP addresses with unverified vulnerabilities."""
        insecure_df = self.insecure_df
        unverif_df = insecure_df[insecure_df["type"] != "Insecure Protocol"]
        unverif_df = unverif_df.copy()
        unverif_df["potential_vulns"] = (
            unverif_df["potential_vulns"].sort_values().apply(lambda x: sorted(x))
        )
        unverif_df["potential_vulns"] = unverif_df["potential_vulns"].astype("str")
        unverif_df = (
            unverif_df[["potential_vulns", "ip"]]
            .drop_duplicates(keep="first")
            .reset_index(drop=True)
        )

        return len(unverif_df.index)

    def verif_vulns(self):
        """Return a dataframe with each CVE, the associated IPs and the affected ports."""
        vulns_df = self.vulns_df
        verif_vulns = (
            vulns_df[["cve", "ip", "port"]]
            .groupby("cve")
            .agg(lambda x: "  ".join(set(x)))
            .reset_index()
        )

        # Empty table check:
        checkEmptyTable(verif_vulns)

        return verif_vulns

    def verif_vulns_summary(self):
        """Return summary dataframe for verified vulns."""
        vulns_df = self.vulns_df
        verif_vulns_summary = (
            vulns_df[["cve", "ip", "port", "summary"]]
            .groupby("cve")
            .agg(lambda x: "  ".join(set(x)))
            .reset_index()
        )

        verif_vulns_summary = verif_vulns_summary.rename(
            columns={
                "cve": "CVE",
                "ip": "IP",
                "port": "Port",
                "summary": "Summary",
            }
        )
        return verif_vulns_summary

    def perChngVuln(self, option):
        "Consolidated percent change function for the insec dev & sus vuln page metrics"
        [prevStart, prevEnd] = getPrevPeriod(self.end_date)
        prev_insecure_df = query_shodan(
            self.org_uid,
            prevStart,
            prevEnd,
            "vw_shodanvulns_suspected",
        )
        [currTotal, prevTotal] = [1, 1]
        if option == "ports":
            prev_risky_assets = self.isolate_risky_assets(prev_insecure_df)
            prev_pro_count = prev_risky_assets.groupby(["protocol"], as_index=False)[
                "protocol"
            ].agg({"id_count": "count"})
            prevTotal = prev_pro_count["id_count"].sum()
            currTotal = self.risky_ports_count()

        elif option == "verifvuln":
            prev_vulns_df = query_shodan(
                self.org_uid, prevStart, prevEnd, "vw_shodanvulns_verified"
            )
            prev_vulns_df["port"] = prev_vulns_df["port"].astype(str)
            prev_verif_vulns = (
                prev_vulns_df[["cve", "ip", "port"]]
                .groupby("cve")
                .agg(lambda x: "  ".join(set(x)))
                .reset_index()
            )
            if len(prev_verif_vulns) > 0:
                prev_verif_vulns["count"] = (
                    prev_verif_vulns["ip"].str.split("  ").str.len()
                )
                prev_verifVulns = prev_verif_vulns["count"].sum()
            else:
                prev_verifVulns = 0
            prevTotal = prev_verifVulns
            currTotal = self.total_verif_vulns()

        elif option == "susvuln":
            prev_unverif_df = prev_insecure_df[
                prev_insecure_df["type"] != "Insecure Protocol"
            ]
            prev_unverif_df = prev_unverif_df.copy()
            prev_unverif_df["potential_vulns"] = (
                prev_unverif_df["potential_vulns"]
                .sort_values()
                .apply(lambda x: sorted(x))
            )
            prev_unverif_df["potential_vulns"] = prev_unverif_df[
                "potential_vulns"
            ].astype("str")
            prev_unverif_df = (
                prev_unverif_df[["potential_vulns", "ip"]]
                .drop_duplicates(keep="first")
                .reset_index(drop=True)
            )
            prevTotal = len(prev_unverif_df.index)
            currTotal = self.unverified_vuln_count()

        return percentChangeStr(percentChange(prevTotal, currTotal))


class Cyber_Six:
    """Dark web and Cyber Six data class."""

    def __init__(self, trending_start_date, start_date, end_date, org_uid):
        """Initialize Cybersixgill vulns and malware class."""
        self.trending_start_date = trending_start_date
        self.start_date = start_date
        self.end_date = end_date
        self.org_uid = org_uid

        dark_web_mentions = query_darkweb(
            org_uid,
            start_date,
            end_date,
            "mentions",
        )
        dark_web_mentions = dark_web_mentions.drop(
            columns=["organizations_uid", "mentions_uid"],
            errors="ignore",
        )
        self.dark_web_mentions = dark_web_mentions

        alerts = query_darkweb(
            org_uid,
            start_date,
            end_date,
            "alerts",
        )
        alerts = alerts.drop(
            columns=["organizations_uid", "alerts_uid"],
            errors="ignore",
        )
        self.alerts = alerts

        top_cves = query_darkweb_cves(
            "top_cves",
        )
        top_cves = top_cves[top_cves["date"] == top_cves["date"].max()]
        self.top_cves = top_cves

    def dark_web_count(self):
        """Get total number of dark web mentions."""
        return len(self.alerts.index)

    def dark_web_date(self):
        """Get dark web mentions by date."""
        trending_dark_web_mentions = query_darkweb(
            self.org_uid,
            self.trending_start_date,
            self.end_date,
            "vw_darkweb_mentionsbydate",
        )

        dark_mentions = query_darkweb(
            self.org_uid,
            self.trending_start_date,
            self.end_date,
            "vw_darkweb_mentionsbydate",
        )
        [
            p1_start,
            p1_end,
            p2_start,
            p2_end,
            p3_start,
            p3_end,
            p4_start,
            p4_end,
            p5_start,
            p5_end,
            p6_start,
            p6_end,
        ] = prevSixPeriods(self.end_date)

        # Group mention counts by report period
        period1 = dark_mentions.loc[
            ((dark_mentions["date"] >= p1_start) & (dark_mentions["date"] <= p1_end))
        ]
        period2 = dark_mentions.loc[
            ((dark_mentions["date"] >= p2_start) & (dark_mentions["date"] <= p2_end))
        ]
        period3 = dark_mentions.loc[
            ((dark_mentions["date"] >= p3_start) & (dark_mentions["date"] <= p3_end))
        ]
        period4 = dark_mentions.loc[
            ((dark_mentions["date"] >= p4_start) & (dark_mentions["date"] <= p4_end))
        ]
        period5 = dark_mentions.loc[
            ((dark_mentions["date"] >= p5_start) & (dark_mentions["date"] <= p5_end))
        ]
        period6 = dark_mentions.loc[
            ((dark_mentions["date"] >= p6_start) & (dark_mentions["date"] <= p6_end))
        ]

        # Aggregate each report period into a single row
        df2 = pd.concat(
            (
                period1[["Count"]].sum().to_frame().T,
                period2[["Count"]].sum().to_frame().T,
                period3[["Count"]].sum().to_frame().T,
                period4[["Count"]].sum().to_frame().T,
                period5[["Count"]].sum().to_frame().T,
                period6[["Count"]].sum().to_frame().T,
            ),
            ignore_index=True,
        )
        df2["date"] = [p1_end, p2_end, p3_end, p4_end, p5_end, p6_end]
        df2["date"] = pd.to_datetime(df2["date"], utc=True)
        df2["date"] = df2["date"].dt.strftime("%b %d")
        df2 = df2.set_index("date")
        df2 = df2.astype({"Count": float})
        df2 = df2.rename(columns={"Count": "Mentions Count"})

        return df2

    def social_media_most_act(self):
        """Get most active social media posts."""
        soc_med_most_act = query_darkweb(
            self.org_uid,
            self.start_date,
            self.end_date,
            "vw_darkweb_socmedia_mostactposts",
        )
        soc_med_most_act = soc_med_most_act.drop(
            columns=["organizations_uid", "date"],
            errors="ignore",
        )
        soc_med_most_act = soc_med_most_act[:4]
        # Translate title field to english
        soc_med_most_act = translate(soc_med_most_act, ["Title"])
        soc_med_most_act["Title"] = soc_med_most_act["Title"].str[:100]
        soc_med_most_act = soc_med_most_act.replace(r"^\s*$", "Untitled", regex=True)

        # Empty table check:
        checkEmptyTable(soc_med_most_act)

        return soc_med_most_act

    def dark_web_most_act(self):
        """Get most active dark web posts."""
        dark_web_most_act = query_darkweb(
            self.org_uid,
            self.start_date,
            self.end_date,
            "vw_darkweb_mostactposts",
        )
        dark_web_most_act = dark_web_most_act.drop(
            columns=["organizations_uid", "date"],
            errors="ignore",
        )
        dark_web_most_act = dark_web_most_act[:5]
        # Translate title field to english
        dark_web_most_act = translate(dark_web_most_act, ["Title"])
        dark_web_most_act["Title"] = dark_web_most_act["Title"].str[:80]
        dark_web_most_act = dark_web_most_act.replace(r"^\s*$", "Untitled", regex=True)

        # Empty table check:
        checkEmptyTable(dark_web_most_act)

        return dark_web_most_act

    def asset_alerts(self):
        """Get top executive mentions."""
        asset_alerts = query_darkweb(
            self.org_uid,
            self.start_date,
            self.end_date,
            "vw_darkweb_assetalerts",
        )
        asset_alerts = asset_alerts.drop(
            columns=["organizations_uid", "date"],
            errors="ignore",
        )
        asset_alerts = asset_alerts[:4]
        asset_alerts["Title"] = asset_alerts["Title"].str[:100]

        # Empty table check:
        checkEmptyTable(asset_alerts)

        return asset_alerts

    def alerts_exec(self):
        """Get top executive alerts."""
        alerts_exec = query_darkweb(
            self.org_uid,
            self.start_date,
            self.end_date,
            "vw_darkweb_execalerts",
        )
        alerts_exec = alerts_exec.drop(
            columns=["organizations_uid", "date"],
            errors="ignore",
        )
        alerts_exec = alerts_exec[:10]
        alerts_exec["Title"] = alerts_exec["Title"].str[:100]

        # Empty table check:
        checkEmptyTable(alerts_exec)

        return alerts_exec

    def dark_web_bad_actors(self):
        """Get dark web bad actors."""
        dark_web_bad_actors = query_darkweb(
            self.org_uid,
            self.start_date,
            self.end_date,
            "vw_darkweb_threatactors",
        )
        dark_web_bad_actors = dark_web_bad_actors.drop(
            columns=["organizations_uid", "date"],
            errors="ignore",
        )
        dark_web_bad_actors = dark_web_bad_actors.groupby(
            "Creator", as_index=False
        ).max()
        dark_web_bad_actors = dark_web_bad_actors.sort_values(
            by=["Grade"], ascending=False
        )[:5]

        # Empty table check:
        checkEmptyTable(dark_web_bad_actors)

        return dark_web_bad_actors

    def alerts_threats(self):
        """Get threat alerts."""
        alerts_threats = query_darkweb(
            self.org_uid,
            self.start_date,
            self.end_date,
            "vw_darkweb_potentialthreats",
        )
        alerts_threats = alerts_threats.drop(
            columns=["organizations_uid", "date"],
            errors="ignore",
        )
        alerts_threats = (
            alerts_threats.groupby(["Site", "Threats"])["Threats"]
            .count()
            .nlargest(5)
            .reset_index(name="Events")
        )
        alerts_threats["Threats"] = alerts_threats["Threats"].str[:50]

        # Empty table check:
        checkEmptyTable(alerts_threats)

        return alerts_threats

    def dark_web_sites(self):
        """Get mentions by dark web sites (top 10)."""
        dark_web_sites = query_darkweb(
            self.org_uid,
            self.start_date,
            self.end_date,
            "vw_darkweb_sites",
        )
        dark_web_sites = dark_web_sites.drop(
            columns=["organizations_uid", "date"],
            errors="ignore",
        )
        dark_web_sites = (
            dark_web_sites.groupby(["Site"])["Site"]
            .count()
            .nlargest(10)
            .reset_index(name="count")
        )

        # Empty table check:
        checkEmptyTable(dark_web_sites)

        return dark_web_sites

    def invite_only_markets(self):
        """Get alerts in invite-only markets."""
        markets = query_darkweb(
            self.org_uid,
            self.start_date,
            self.end_date,
            "vw_darkweb_inviteonlymarkets",
        )
        markets = markets.drop(
            columns=["organizations_uid", "date"],
            errors="ignore",
        )
        markets = (
            markets.groupby(["Site"])["Site"]
            .count()
            .nlargest(10)
            .reset_index(name="Alerts")
        )

        # Empty table check:
        checkEmptyTable(markets)

        return markets

    def top_cve_table(self):
        """Get top CVEs."""
        top_cves = self.top_cves
        top_cves["summary_short"] = top_cves["summary"].str[:400]
        top_cve_table = top_cves[["cve_id", "summary_short"]]
        top_cve_table = top_cve_table.rename(
            columns={"cve_id": "CVE", "summary_short": "Description"}
        )
        top_cve_table["Identified By"] = "Cybersixgill"

        # Get all CVEs found in shodan
        shodan_cves = Malware_Vulns(
            self.start_date, self.end_date, self.org_uid
        ).all_cves()
        for cve_index, cve_row in top_cve_table.iterrows():
            if cve_row["CVE"] in shodan_cves:
                print("we got a match")
                print(cve_row["CVE"])
                top_cve_table.at[cve_index, "Identified By"] += ",   Shodan"

        # Empty table check:
        checkEmptyTable(top_cve_table)

        return top_cve_table

    def perChngDark(self, option):
        "Consolidated percent change function for the dark web activity page metrics"
        [prevStart, prevEnd] = getPrevPeriod(self.end_date)
        [currTotal, prevTotal] = [1, 1]
        if option == "alerts":
            prev_alerts = query_darkweb(
                self.org_uid,
                prevStart,
                prevEnd,
                "alerts",
            )
            prevTotal = len(prev_alerts.index)
            currTotal = len(self.alerts.index)
        return percentChangeStr(percentChange(prevTotal, currTotal))

    # ---------- v Dark Web Usage WIP v ------------

    def checkDarkUsage(self):
        """Checks if stakeholder is making good use of dark web/cybersixgill resources"""
        # Check organization's first report date
        firstReportDate = get_org_first_report_date(self.org_uid).iloc[0, 0]
        firstReportDate = datetime.datetime(2022, 1, 1)  # Testing
        if firstReportDate is None or firstReportDate == "":
            return "No first report date"
        else:
            # If valid first report date,
            firstReportDate = firstReportDate.date()
            # check if stakeholder has 3 report periods of data history available
            [
                p1_start,
                p1_end,
                p2_start,
                p2_end,
                p3_start,
                p3_end,
                p4_start,
                p4_end,
                p5_start,
                p5_end,
                p6_start,
                p6_end,
            ] = prevSixPeriods(self.end_date)

            if firstReportDate <= p4_start:
                # If stakeholder has sufficient data history
                # Get alert data for past 3 report periods
                Alerts = query_darkweb(
                    self.org_uid,
                    p3_start,
                    p6_end,
                    "alerts",
                )
                p4_alert = Alerts.loc[
                    ((Alerts["date"] >= p4_start) & (Alerts["date"] <= p4_end))
                ]
                p5_alert = Alerts.loc[
                    ((Alerts["date"] >= p5_start) & (Alerts["date"] <= p5_end))
                ]
                p6_alert = Alerts.loc[
                    ((Alerts["date"] >= p6_start) & (Alerts["date"] <= p6_end))
                ]
                alertCounts = [
                    len(p4_alert.index),
                    len(p5_alert.index),
                    len(p6_alert.index),
                ]

                # Get mention data for past 3 report periods
                Mentions = query_darkweb(
                    self.org_uid,
                    p4_start,
                    p6_end,
                    "vw_darkweb_mentionsbydate",
                )
                p4_mention = Mentions.loc[
                    ((Mentions["date"] >= p4_start) & (Mentions["date"] <= p4_end))
                ]
                p5_mention = Mentions.loc[
                    ((Mentions["date"] >= p5_start) & (Mentions["date"] <= p5_end))
                ]
                p6_mention = Mentions.loc[
                    ((Mentions["date"] >= p6_start) & (Mentions["date"] <= p6_end))
                ]
                mentionCounts = [
                    p4_mention[["Count"]].sum()[0],
                    p5_mention[["Count"]].sum()[0],
                    p6_mention[["Count"]].sum()[0],
                ]

                # Get dark web post counts for past 3 report periods
                Posts = query_darkweb(
                    self.org_uid,
                    p4_start,
                    p6_end,
                    "vw_darkweb_mostactposts",
                )
                p4_posts = Posts.loc[
                    ((Posts["date"] >= p4_start) & (Posts["date"] <= p4_end))
                ]
                p5_posts = Posts.loc[
                    ((Posts["date"] >= p5_start) & (Posts["date"] <= p5_end))
                ]
                p6_posts = Posts.loc[
                    ((Posts["date"] >= p6_start) & (Posts["date"] <= p6_end))
                ]
                postCounts = [
                    len(p4_posts),
                    len(p5_posts),
                    len(p6_posts),
                ]

                # Get dark web threat counts for past 3 report periods
                Threats = query_darkweb(
                    self.org_uid,
                    p4_start,
                    p6_end,
                    "vw_darkweb_potentialthreats",
                )
                p4_threats = Threats.loc[
                    ((Threats["date"] >= p4_start) & (Threats["date"] <= p4_end))
                ]
                p5_threats = Threats.loc[
                    ((Threats["date"] >= p5_start) & (Threats["date"] <= p5_end))
                ]
                p6_threats = Threats.loc[
                    ((Threats["date"] >= p6_start) & (Threats["date"] <= p6_end))
                ]

                threatCounts = [len(p4_threats), len(p5_threats), len(p6_threats)]

                print("Alert Counts: ", alertCounts)
                print("Mention Counts: ", mentionCounts)
                print("Post Counts: ", postCounts)
                print("Threat Counts: ", threatCounts)

                # Check if dark web stats are below thresholds
                if (
                    all(x < 7 for x in alertCounts)
                    and all(x < 16 for x in mentionCounts)
                    and all(x < 11 for x in postCounts)
                    and all(x < 3 for x in threatCounts)
                ):
                    # Organization should be downgraded to core report
                    return "Core"
                else:
                    # Organization should continue with premium report
                    return "Premium"
            else:
                # If stakeholder has insufficient data history
                return "Insufficient data history"
