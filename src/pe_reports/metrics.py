"""Class methods for report metrics."""

# Import query functions
# Standard Python Libraries
import datetime

# Third-Party Libraries
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
)
from .data.translator import translate


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
        # df = df[["mod_date", "no_password", "password_included"]].copy()
        idx = pd.date_range(self.trending_start_date, self.end_date)
        df = df.set_index("mod_date").reindex(idx).fillna(0.0).rename_axis("added_date")
        group_limit = self.end_date + datetime.timedelta(1)
        df = df.groupby(
            pd.Grouper(level="added_date", freq="7d", origin=group_limit)
        ).sum()
        df["modified_date"] = df.index
        df["modified_date"] = df["modified_date"].dt.strftime("%b %d")
        df = df.set_index("modified_date")
        df = df.rename(
            columns={
                "password_included": "Passwords Included",
                "no_password": "No Password",
            }
        )
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
        view_df.sort_values("breach_name", inplace=True)
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
        """Return total count of insecure ports."""
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

    def ip_count(self):
        """Return the number of total ips with suspected and confirmed vulns."""
        vulns_df = self.vulns_df
        unverif_df = self.insecure_df

        combined_ips = vulns_df["ip"].append(unverif_df["ip"], ignore_index=True)

        return len(pd.unique(combined_ips))

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

    def __init__(
        self,
        trending_start_date,
        start_date,
        end_date,
        org_uid,
        all_cves_df,
        soc_med_included,
    ):
        """Initialize Cybersixgill vulns and malware class."""
        self.trending_start_date = trending_start_date
        self.start_date = start_date
        self.end_date = end_date
        self.org_uid = org_uid
        self.all_cves_df = all_cves_df
        self.soc_med_included = soc_med_included
        self.soc_med_platforms = [
            "twitter",
            "Twitter",
            "reddit",
            "Reddit",
            "Parler",
            "parler",
            "linkedin",
            "Linkedin",
            "discord",
            "forum_discord",
            "raddle",
            "telegram",
            "jabber",
            "ICQ",
            "icq",
            "mastodon",
        ]
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
        if not soc_med_included:
            dark_web_mentions = dark_web_mentions[
                ~dark_web_mentions["site"].isin(self.soc_med_platforms)
            ]
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
        if not soc_med_included:
            alerts = alerts[~alerts["site"].isin(self.soc_med_platforms)]
        self.alerts = alerts

        top_cves = query_darkweb_cves(
            "top_cves",
        )
        top_cves = top_cves[top_cves["date"] == top_cves["date"].max()]
        self.top_cves = top_cves

    def dark_web_count(self):
        """Get total number of dark web alerts."""
        return len(self.alerts.index)

    def dark_web_mentions_count(self):
        """Get total number of dark web mentions."""
        return len(self.dark_web_mentions)

    def dark_web_date(self):
        """Get dark web mentions by date."""
        trending_dark_web_mentions = query_darkweb(
            self.org_uid,
            self.trending_start_date,
            self.end_date,
            "vw_darkweb_mentionsbydate",
        )
        dark_web_date = trending_dark_web_mentions.drop(
            columns=["organizations_uid"],
            errors="ignore",
        )
        idx = pd.date_range(self.trending_start_date, self.end_date)
        dark_web_date = (
            dark_web_date.set_index("date").reindex(idx).fillna(0.0).rename_axis("date")
        )
        group_limit = self.end_date + datetime.timedelta(1)
        dark_web_date = dark_web_date.groupby(
            pd.Grouper(level="date", freq="7d", origin=group_limit)
        ).sum()
        dark_web_date["date"] = dark_web_date.index
        dark_web_date["date"] = dark_web_date["date"].dt.strftime("%m/%d")
        dark_web_date = dark_web_date.set_index("date")
        dark_web_date = dark_web_date[["Count"]]
        return dark_web_date

    def create_count_df(self):
        """Retrieve dataframe of counts by mention type."""
        name = []
        value = []
        markets = query_darkweb(
            self.org_uid,
            self.start_date,
            self.end_date,
            "vw_darkweb_inviteonlymarkets",
        )
        if len(markets) > 0:
            name.append("INVITE ONLY MARKET")
            value.append(len(markets))

        if self.soc_med_included:
            soc_med = query_darkweb(
                self.org_uid,
                self.start_date,
                self.end_date,
                "vw_darkweb_socmedia_mostactposts",
            )
            if len(soc_med) > 0:
                name.append("SOCIAL MEDIA")
                value.append(len(soc_med))

        dark_web_forum = query_darkweb(
            self.org_uid,
            self.start_date,
            self.end_date,
            "vw_darkweb_mostactposts",
        )
        if len(dark_web_forum) > 0:
            name.append("DARK WEB FORUM")
            value.append(len(dark_web_forum))

        alerts_exec = query_darkweb(
            self.org_uid,
            self.start_date,
            self.end_date,
            "vw_darkweb_execalerts",
        )
        if len(alerts_exec) > 0:
            name.append("EXECUTIVES")
            value.append(len(alerts_exec))

        if name:
            circle_df = pd.DataFrame({"Name": name, "Value": value})

            return circle_df
        else:
            return 0

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
        soc_med_most_act = soc_med_most_act[:10]
        # Translate title field to english
        soc_med_most_act = translate(soc_med_most_act, ["Title"])
        soc_med_most_act["Title"] = soc_med_most_act["Title"].str[:200]
        soc_med_most_act = soc_med_most_act.replace(r"^\s*$", "Untitled", regex=True)
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
        # Translate title field to english
        dark_web_most_act = dark_web_most_act[:10]
        dark_web_most_act = translate(dark_web_most_act, ["Title"])
        dark_web_most_act["Title"] = dark_web_most_act["Title"].str[:200]
        dark_web_most_act = dark_web_most_act.replace(r"^\s*$", "Untitled", regex=True)
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
        if not self.soc_med_included:
            asset_alerts = asset_alerts[
                ~asset_alerts["Site"].isin(self.soc_med_platforms)
            ]
        asset_alerts["Title"] = asset_alerts["Title"].str[:200]
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
        if not self.soc_med_included:
            alerts_exec = alerts_exec[~alerts_exec["Site"].isin(self.soc_med_platforms)]
        alerts_exec["Title"] = alerts_exec["Title"].str[:200]
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
        )
        dark_web_bad_actors = dark_web_bad_actors[:10]
        dark_web_bad_actors = translate(dark_web_bad_actors, ["Creator"])
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
        if not self.soc_med_included:
            alerts_threats = alerts_threats[
                ~alerts_threats["Site"].isin(self.soc_med_platforms)
            ]
        alerts_threats = (
            alerts_threats.groupby(["Site", "Threats"])["Threats"]
            .count()
            .nlargest(10)
            .reset_index(name="Events")
        )
        alerts_threats["Threats"] = alerts_threats["Threats"].str[:200]
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
        if not self.soc_med_included:
            dark_web_sites = dark_web_sites[
                ~dark_web_sites["Site"].isin(self.soc_med_platforms)
            ]
        dark_web_sites = (
            dark_web_sites.groupby(["Site"])["Site"]
            .count()
            .nlargest(10)
            .reset_index(name="count")
        )
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
        return markets

    def top_cve_table(self):
        """Get top CVEs."""
        top_cves = self.top_cves
        top_cves["summary_short"] = top_cves["summary"].str[:500]
        top_cve_table = top_cves[["cve_id", "summary_short"]]
        top_cve_table = top_cve_table.rename(
            columns={"cve_id": "CVE", "summary_short": "Description"}
        )
        top_cve_table["Identified By"] = "Cybersixgill"

        # Get all CVEs found in shodan
        shodan_cves = self.all_cves_df
        for cve_index, cve_row in top_cve_table.iterrows():
            if cve_row["CVE"] in shodan_cves:
                print("we got a match")
                print(cve_row["CVE"])
                top_cve_table.at[cve_index, "Identified By"] += ",   Shodan"

        return top_cve_table


class Core_Cyber_Six:
    """Collect relevant CyberSix data for a given Core report."""

    def __init__(
        self,
        all_cves_df,
    ):
        """Initialize Core CyberSix class."""
        self.all_cves_df = all_cves_df
        top_cves = query_darkweb_cves(
            "top_cves",
        )
        top_cves = top_cves[top_cves["date"] == top_cves["date"].max()]
        self.top_cves = top_cves

    def top_cve_table(self):
        """Get top CVEs."""
        top_cves = self.top_cves
        top_cves["summary_short"] = top_cves["summary"].str[:500]
        top_cve_table = top_cves[["cve_id", "summary_short"]]
        top_cve_table = top_cve_table.rename(
            columns={"cve_id": "CVE", "summary_short": "Description"}
        )
        top_cve_table["Identified By"] = "Cybersixgill"

        # Get all CVEs found in shodan
        shodan_cves = self.all_cves_df
        for cve_index, cve_row in top_cve_table.iterrows():
            if cve_row["CVE"] in shodan_cves:
                top_cve_table.at[cve_index, "Identified By"] += ",   Shodan"

        return top_cve_table
