"""Class methods for report metrics."""

# Import query functions
# Third-Party Libraries
from data.db_query import (
    query_cyberSix_creds,
    query_darkweb,
    query_darkweb_cves,
    query_domMasq,
    query_hibp_view,
    query_shodan,
)
import pandas as pd


class Credentials:
    """Credentials class."""

    def __init__(self, start_date, end_date, org_uid):
        """Initialize credentials class."""
        self.start_date = start_date
        self.end_date = end_date
        self.org_uid = org_uid
        self.query_cyberSix_creds = query_cyberSix_creds(org_uid, start_date, end_date)
        self.query_hibp_view = query_hibp_view(org_uid, start_date, end_date)

    def by_days(self):
        """Return number of credentials by day."""
        c6_df = self.query_cyberSix_creds
        hibp_df = self.query_hibp_view
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

    def breaches(self):
        """Return total number of breaches."""
        all_breaches = pd.concat(
            self.query_hibp_view["breach_name"],
            self.query_cyberSix_creds["breach_name"],
        )
        return all_breaches.nunique()

    def breach_appendix(self):
        """Return breach name and description to be added to the appendix."""
        hibp_df = self.query_hibp_view
        c6_df = self.query_cyberSix_creds
        c6_df_2 = c6_df[["breach_name", "description"]]
        c6_df_2 = c6_df_2.rename(columns={"create_time": "modified_date"})
        view_df_2 = hibp_df[["breach_name", "description"]]
        view_df_2 = view_df_2.append(c6_df_2, ignore_index=True)

        view_df_2.drop_duplicates()
        return view_df_2[["breach_name", "description"]]

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

    def password(self):
        """Return total number of credentials with passwords."""
        pw_creds_csg = len(
            self.query_cyberSix_creds[self.query_cyberSix_creds["password_included"]]
        )
        pw_creds_hibp = len(
            self.query_hibp_view[self.query_hibp_view["password_included"]]
        )
        return pw_creds_csg + pw_creds_hibp

    def total(self):
        """Return total number of credentials found in breaches."""
        df_cred_csg = self.query_cyberSix_creds.shape[0]
        df_cred_hibp = self.query_hibp_view.shape[0]
        return df_cred_csg + df_cred_hibp


class Domains_Masqs:
    """Domains Masquerading class."""

    def __init__(self, start_date, end_date, org_uid):
        """Initialize domains masquerading class."""
        self.start_date = start_date
        self.end_date = end_date
        self.org_uid = org_uid
        df = query_domMasq(org_uid, start_date, end_date)
        self.df_mal = df[df["malicious"]]

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
            domain_sum = domain_sum[:25]
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

    def utlds(self):
        """Return count of unique top level domains."""
        mal_df = self.df_mal

        if mal_df > 0:
            mal_df["tld"] = (
                mal_df["domain_permutation"]
                .str.split(".")
                .str[-1]
                .str.split("/")
                .str[0]
            )
            utlds = len(mal_df["tld"].unique())
        else:
            utlds = 0

        return utlds


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
            start_date,
            end_date,
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
        dark_web_most_act = dark_web_mentions[["comments_count", "title", "content"]]
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
        dark_web_most_act["content"] = dark_web_most_act["content"].str[:100]
        dark_web_most_act = dark_web_most_act.rename(
            columns={"title": "Title", "content": "Content"}
        )
        dark_web_most_act["Title"] = dark_web_most_act["Title"].str[:50]
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

    def top_cve_table(self):
        """Get top CVEs."""
        top_cves = self.top_cves
        top_cve_table = top_cves[["cve_id", "summary"]]
        top_cve_table["summary"] = top_cve_table["summary"].str[:400]
        top_cve_table = top_cve_table.rename(
            columns={"cve_id": "CVE", "summary": "Description"}
        )
        return top_cve_table
