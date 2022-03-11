"""Class methods for report metrics."""

# Import query functions
# Third-Party Libraries
import pandas as pd

from .data.db_query import (
    query_creds_vw,
    query_darkweb,
    query_darkweb_cves,
    query_domMasq,
    query_domMasq_alerts,
    query_shodan,
)


class Credentials:
    """Credentials class."""

    def __init__(self, start_date, end_date, org_uid):
        """Initialize credentials class."""
        self.start_date = start_date
        self.end_date = end_date
        self.org_uid = org_uid
        self.creds_view = query_creds_vw(org_uid, start_date, end_date)

    def by_days(self):
        """Return number of credentials by day."""
        df = self.creds_view
        df = df[["modified_date", "password_included", "email"]].copy()
        df.loc[:, "modified_date"] = pd.to_datetime(df["modified_date"]).dt.date
        df = df.groupby(["modified_date", "password_included"], as_index=False).agg(
            {"email": ["count"]}
        )
        idx = pd.date_range(self.start_date, self.end_date)
        df.columns = df.columns.droplevel(1)
        df = (
            df.pivot(index="modified_date", columns="password_included", values="email")
            .fillna(0)
            .reset_index()
            .rename_axis(None)
        )
        df.columns.name = None
        df = (
            df.set_index("modified_date")
            .reindex(idx)
            .fillna(0.0)
            .rename_axis("added_date")
        )
        df["modified_date"] = df.index
        df["modified_date"] = df["modified_date"].dt.strftime("%m/%d/%y")
        df = df.set_index("modified_date")
        df = df.rename(columns={True: "Passwords Included", False: "No Password"})
        if len(df.columns) == 0:
            df["Passwords Included"] = 0

        return df

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
        view_df = self.creds_view
        view_df = view_df[
            [
                "breach_name",
                "modified_date",
                "description",
                "breach_date",
                "password_included",
                "email",
            ]
        ]

        breach_df = view_df.groupby(
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

        return breach_det_df

    def password(self):
        """Return total number of credentials with passwords."""
        pw_creds = len(self.creds_view[self.creds_view["password_included"]])
        return pw_creds

    def total(self):
        """Return total number of credentials found in breaches."""
        df_cred = self.creds_view.shape[0]
        return df_cred


class Domains_Masqs:
    """Domains Masquerading class."""

    def __init__(self, start_date, end_date, org_uid):
        """Initialize domains masquerading class."""
        self.start_date = start_date
        self.end_date = end_date
        self.org_uid = org_uid
        df = query_domMasq(org_uid, start_date, end_date)
        self.df_mal = df[df["malicious"]]
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
        return dom_alerts_df

    def alerts_sum(self):
        """Return domain alerts summary."""
        dom_alerts_sum = self.dom_alerts_df[
            ["message", "date", "previous_value", "new_value"]
        ]
        return dom_alerts_sum


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
            "shodan_insecure_protocols_unverified_vulns",
        )
        self.insecure_df = insecure_df

        vulns_df = query_shodan(org_uid, start_date, end_date, "shodan_verified_vulns")
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
        return insecure[["ip", "protocol"]].drop_duplicates(keep="first")

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

    def unverified_cve(self):
        """Return top 15 unverified CVEs and their counts."""
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
        unverif_df["count"] = unverif_df["potential_vulns"].str.split(",").str.len()
        unverif_df = unverif_df[["ip", "count"]]
        unverif_df = unverif_df.sort_values(by=["count"], ascending=False)
        unverif_df = unverif_df[:15].reset_index(drop=True)
        return unverif_df

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


class Cyber_Six:
    """Dark web and Cyber Six data class."""

    def __init__(self, start_date, end_date, org_uid):
        """Initialize Shodan vulns and malware class."""
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

    def alerts_exec(self):
        """Get top executive mentions."""
        alerts = self.alerts
        alerts_exec = alerts[["site", "title"]]
        alerts_exec = alerts_exec[alerts_exec["site"] != "NaN"]
        alerts_exec = alerts_exec[alerts_exec["site"] != ""]
        alerts_exec = (
            alerts_exec.groupby(["site", "title"])["title"]
            .count()
            .nlargest(10)
            .reset_index(name="Events")
        )
        alerts_exec = alerts_exec.rename(columns={"site": "Site", "title": "Title"})
        return alerts_exec

    def alerts_threats(self):
        """Get threat alerts."""
        alerts = self.alerts
        alerts_threats = alerts[["site", "threats"]]
        alerts_threats = alerts_threats[alerts_threats["site"] != "NaN"]
        alerts_threats = alerts_threats[alerts_threats["site"] != ""]
        alerts_threats = (
            alerts_threats.groupby(["site", "threats"])["threats"]
            .count()
            .nlargest(5)
            .reset_index(name="Events")
        )
        alerts_threats["threats"] = alerts_threats["threats"].str.strip("{}")
        alerts_threats["threats"] = alerts_threats["threats"].str[:50]
        alerts_threats = alerts_threats.rename(
            columns={"site": "Site", "threats": "Threats"}
        )
        return alerts_threats

    def dark_web_bad_actors(self):
        """Get dark web bad actors."""
        dark_web_mentions = self.dark_web_mentions
        dark_web_bad_actors = dark_web_mentions[["creator", "rep_grade"]]
        dark_web_bad_actors = dark_web_bad_actors.groupby(
            "creator", as_index=False
        ).max()
        dark_web_bad_actors = dark_web_bad_actors.sort_values(
            by=["rep_grade"], ascending=False
        )[:10]
        dark_web_bad_actors["rep_grade"] = (
            dark_web_bad_actors["rep_grade"].astype(float).round(decimals=3)
        )
        dark_web_bad_actors = dark_web_bad_actors.rename(
            columns={"creator": "Creator", "rep_grade": "Grade"}
        )
        return dark_web_bad_actors

    def dark_web_content(self):
        """Get dark web categories."""
        dark_web_mentions = self.dark_web_mentions
        dark_web_content = dark_web_mentions[["category"]]
        dark_web_content = (
            dark_web_content.groupby(["category"])["category"]
            .count()
            .nlargest(10)
            .reset_index(name="count")
        )
        return dark_web_content

    def dark_web_count(self):
        """Get total number of dark web mentions."""
        return len(self.dark_web_mentions.index)

    def dark_web_date(self):
        """Get dark web mentions by date."""
        dark_web_mentions = self.dark_web_mentions
        dark_web_date = dark_web_mentions[["date"]]
        dark_web_date = (
            dark_web_date.groupby(["date"])["date"].count().reset_index(name="Count")
        )
        return dark_web_date

    def dark_web_most_act(self):
        """Get most active posts."""
        dark_web_mentions = self.dark_web_mentions
        dark_web_most_act = dark_web_mentions[["title", "comments_count"]]
        dark_web_most_act = dark_web_most_act[
            dark_web_most_act["comments_count"] != "NaN"
        ]
        dark_web_most_act = dark_web_most_act.rename(
            columns={"comments_count": "Comments Count"}
        )
        dark_web_most_act["Comments Count"] = (
            dark_web_most_act["Comments Count"].astype(float).astype(int)
        )
        dark_web_most_act = dark_web_most_act.sort_values(
            by="Comments Count", ascending=False
        )
        dark_web_most_act = dark_web_most_act[:5]
        dark_web_most_act = dark_web_most_act.rename(columns={"title": "Title"})
        dark_web_most_act["Title"] = dark_web_most_act["Title"].str[:100]
        dark_web_most_act = dark_web_most_act.replace(r"^\s*$", "Untitled", regex=True)
        return dark_web_most_act

    def dark_web_sites(self):
        """Get mentions by dark web sites (top 10)."""
        dark_web_mentions = self.dark_web_mentions
        dark_web_sites = dark_web_mentions[["site"]]
        dark_web_sites = (
            dark_web_sites.groupby(["site"])["site"]
            .count()
            .nlargest(10)
            .reset_index(name="count")
        )
        dark_web_sites = dark_web_sites.rename(
            columns={"site": "Site", "count": "Count"}
        )
        return dark_web_sites

    def dark_web_tags(self):
        """Get dark web notable tags."""
        dark_web_mentions = self.dark_web_mentions
        dark_web_tags = dark_web_mentions[["tags"]]
        dark_web_tags = dark_web_tags[dark_web_tags["tags"] != "NaN"]
        dark_web_tags = (
            dark_web_tags.groupby(["tags"])["tags"]
            .count()
            .nlargest(8)
            .reset_index(name="Events")
        )
        dark_web_tags["tags"] = dark_web_tags["tags"].str.strip("{}")
        dark_web_tags["tags"] = dark_web_tags["tags"].str.replace(
            ",", ", ", regex=False
        )
        dark_web_tags = dark_web_tags.rename(columns={"tags": "Tags"})
        return dark_web_tags

    def alerts_site(self):
        """Get alerts in invite-only markets."""
        alerts_site = self.alerts[["site"]]
        alerts_site = alerts_site[alerts_site["site"] != "NaN"]
        alerts_site = alerts_site[alerts_site["site"] != ""]
        alerts_site = alerts_site[alerts_site["site"].str.startswith("market")]
        alerts_site = (
            alerts_site.groupby(["site"])["site"]
            .count()
            .nlargest(10)
            .reset_index(name="Alerts")
        )
        alerts_site = alerts_site.rename(columns={"site": "Site"})
        return alerts_site

    def top_cve_table(self):
        """Get top CVEs."""
        top_cves = self.top_cves
        top_cves["summary_short"] = top_cves["summary"].str[:400]
        top_cve_table = top_cves[["cve_id", "summary_short"]]
        top_cve_table = top_cve_table.rename(
            columns={"cve_id": "CVE", "summary_short": "Description"}
        )
        return top_cve_table
