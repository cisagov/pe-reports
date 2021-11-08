"""Generate metrics for each page."""
# Standard Python Libraries
from datetime import datetime

# Third-Party Libraries
import numpy as np
import pandas as pd
from pe_db.query import (
    close,
    connect,
    query_cyberSix_creds,
    query_darkweb,
    query_darkweb_cves,
    query_domMasq,
    query_hibp_view,
    query_shodan,
)

# from pe_reports.pe_db.query import query_cyberSix_creds


def credential_metrics(start_date, end_date, org_uid):
    """Calculate compromised credentials metrics and return variables and dataframes."""
    conn = connect()
    view_df = query_hibp_view(conn, org_uid, start_date, end_date)
    conn = connect()

    c6_df = query_cyberSix_creds(conn, org_uid, start_date, end_date)
    c6_df["description"] = (
        c6_df["description"].str.split("Query to find the related").str[0]
    )
    c6_df["password_included"] = np.where(c6_df["password"] != "", True, False)
    c6_df_2 = c6_df[["create_time", "password_included", "email"]]
    c6_df_2 = c6_df_2.rename(columns={"create_time": "modified_date"})

    hibp_df = view_df[["modified_date", "password_included", "email"]]
    hibp_df = hibp_df.append(c6_df_2, ignore_index=True)
    hibp_df["modified_date"] = pd.to_datetime(hibp_df["modified_date"]).dt.date
    creds = len(hibp_df)

    pw_creds = len(hibp_df[hibp_df["password_included"]])

    hibp_df = hibp_df.groupby(
        ["modified_date", "password_included"], as_index=False
    ).agg({"email": ["count"]})
    idx = pd.date_range(start_date, end_date)
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
    c6_df_3 = c6_df[
        [
            "breach_name",
            "create_time",
            "description",
            "breach_date",
            "password_included",
            "email",
        ]
    ]
    c6_df_3 = c6_df_3.rename(columns={"create_time": "modified_date"})
    view_df_2 = view_df[
        [
            "breach_name",
            "modified_date",
            "description",
            "breach_date",
            "password_included",
            "email",
        ]
    ]
    view_df_2 = view_df_2.append(c6_df_3, ignore_index=True)

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
    breach_appendix = breach_df[["breach_name", "description"]]
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

    creds_attach = view_df
    creds_attach2 = c6_df

    # count how many distinct breaches there are
    #
    breach = breach_df["breach_name"].nunique()
    print("there are " + str(breach) + " breaches")

    return (
        creds,
        breach,
        pw_creds,
        ce_date_df,
        breach_det_df,
        creds_attach,
        creds_attach2,
        breach_appendix,
    )


def domain_metrics(idx, org_uid, start_date, end_date):
    """Calculate domain metrics and return variables and dataframes."""
    # Get domain masq data from PE database
    conn = connect()
    df = query_domMasq(conn, org_uid, start_date, end_date)
    close(conn)
    # Filter to domains that were blocklisted
    df_mal = df[df["malicious"]]
    malCount = len(df_mal)
    if malCount > 0:
        domain_sum = df_mal[
            [
                "domain_permutation",
                "ipv4",
                "ipv6",
                "mail_server",
                "name_server",
            ]
        ]
        df_mal["tld"] = (
            df_mal["domain_permutation"].str.split(".").str[-1].str.split("/").str[0]
        )
        utlds = len(df_mal["tld"].unique())
        domain_count = len(domain_sum.index)
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
        df_mal = pd.DataFrame(columns=df.columns.values)
        domain_sum = pd.DataFrame(
            columns=[
                "Domain",
                "IPv4",
                "IPv6",
                "Mail Server",
                "Name Server",
            ]
        )
        domain_count = 0
        utlds = 0
    return df_mal, domain_sum, domain_count, utlds


def malware_vuln_metrics(org_uid, start_date, end_date):
    """Calculate malware association and inferred vulnerability metrics and return variables and dataframes."""
    conn = connect()
    insecure_df = query_shodan(
        conn,
        org_uid,
        start_date,
        end_date,
        "shodan_insecure_protocols_unverified_vulns",
    )
    vulns_df = query_shodan(
        conn, org_uid, start_date, end_date, "shodan_verified_vulns"
    )
    print(vulns_df)
    output_df = query_shodan(conn, org_uid, start_date, end_date, "shodan_assets")

    close(conn)
    # Table: Insecure protocols
    insecure = insecure_df[insecure_df["type"] == "Insecure Protocol"]
    insecure = insecure[
        (insecure["protocol"] != "http") & (insecure["protocol"] != "smtp")
    ]
    risky_assets = insecure[["ip", "protocol"]].drop_duplicates(keep="first")

    # Horizontal bar: insecure protocol count
    pro_count = risky_assets.groupby(["protocol"], as_index=False)["protocol"].agg(
        {"id_count": "count"}
    )

    # Total Open Ports with Insecure protocols
    riskyPortsCount = pro_count["id_count"].sum()

    # Table: Verified Vulnerabilities
    vulns_df["port"] = vulns_df["port"].astype(str)
    verif_vulns = (
        vulns_df[["cve", "ip", "port"]]
        .groupby("cve")
        .agg(lambda x: "  ".join(set(x)))
        .reset_index()
    )
    verif_vulns_summary = (
        vulns_df[["cve", "ip", "port", "summary"]]
        .groupby("cve")
        .agg(lambda x: "  ".join(set(x)))
        .reset_index()
    )
    if len(verif_vulns) > 0:
        verif_vulns["count"] = verif_vulns["ip"].str.split("  ").str.len()
        verifVulns = verif_vulns["count"].sum()
        verif_vulns = verif_vulns.drop(["count"], axis=1)
    else:
        verifVulns = 0

    # Horizaontal Bar: # of unverified CVE's for each IP (TOP 15)
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
    unverifVulnAssets = len(unverif_df.index)
    unverif_df = unverif_df[:15].reset_index(drop=True)

    # Rename sumamry columns
    verif_vulns_summary = verif_vulns_summary.rename(
        columns={
            "cve": "CVE",
            "ip": "IP",
            "port": "Port",
            "summary": "Summary",
        }
    )
    return (
        insecure_df,
        vulns_df,
        output_df,
        pro_count,
        unverif_df,
        risky_assets,
        verif_vulns,
        verif_vulns_summary,
        riskyPortsCount,
        verifVulns,
        unverifVulnAssets,
    )


def mention_metrics(org_uid, start_date, end_date):
    """Calculate malware association metrics and return variables and dataframes."""
    conn = connect()
    dark_web_mentions = query_darkweb(
        conn,
        org_uid,
        start_date,
        end_date,
        "mentions",
    )
    alerts = query_darkweb(
        conn,
        org_uid,
        start_date,
        end_date,
        "alerts",
    )
    top_cves = query_darkweb_cves(
        conn,
        start_date,
        end_date,
        "top_cves",
    )
    # Filter cves to most recent date
    top_cves = top_cves[top_cves["date"] == top_cves["date"].max()]
    close(conn)
    dark_web_mentions = dark_web_mentions.drop(
        columns=["organizations_uid", "mentions_uid"],
        errors="ignore",
    )
    alerts = alerts.drop(
        columns=["organizations_uid", "alerts_uid"],
        errors="ignore",
    )
    # Get total number of Dark Web mentions
    darkWeb = len(dark_web_mentions.index)

    # Get dark web mentions by date
    dark_web_date = dark_web_mentions[["date"]]
    dark_web_date = (
        dark_web_date.groupby(["date"])["date"].count().reset_index(name="Count")
    )
    print(dark_web_date)

    # Get mentions by dark web sites (top 10)
    dark_web_sites = dark_web_mentions[["site"]]
    dark_web_sites = (
        dark_web_sites.groupby(["site"])["site"]
        .count()
        .nlargest(10)
        .reset_index(name="count")
    )
    dark_web_sites = dark_web_sites.rename(columns={"site": "Site", "count": "Count"})

    # Get alert threats
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

    # Get dark web bad actors
    dark_web_bad_actors = dark_web_mentions[["creator", "rep_grade"]]
    dark_web_bad_actors = dark_web_bad_actors.groupby("creator", as_index=False).max()
    dark_web_bad_actors = dark_web_bad_actors.sort_values(
        by=["rep_grade"], ascending=False
    )[:10]
    dark_web_bad_actors["rep_grade"] = (
        dark_web_bad_actors["rep_grade"].astype(float).round(decimals=3)
    )
    dark_web_bad_actors = dark_web_bad_actors.rename(
        columns={"creator": "Creator", "rep_grade": "Grade"}
    )

    # Get dark web notable tags
    dark_web_tags = dark_web_mentions[["tags"]]
    dark_web_tags = dark_web_tags[dark_web_tags["tags"] != "NaN"]
    dark_web_tags = (
        dark_web_tags.groupby(["tags"])["tags"]
        .count()
        .nlargest(8)
        .reset_index(name="Events")
    )
    dark_web_tags["tags"] = dark_web_tags["tags"].str.strip("{}")
    dark_web_tags["tags"] = dark_web_tags["tags"].str.replace(",", ", ", regex=False)
    dark_web_tags = dark_web_tags.rename(columns={"tags": "Tags"})

    # Get dark web categories
    dark_web_content = dark_web_mentions[["category"]]
    dark_web_content = (
        dark_web_content.groupby(["category"])["category"]
        .count()
        .nlargest(10)
        .reset_index(name="count")
    )

    # Get top executive mentions
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

    # Get most active posts
    dark_web_most_act = dark_web_mentions[["comments_count", "title", "content"]]
    dark_web_most_act = dark_web_most_act[dark_web_most_act["comments_count"] != "NaN"]
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

    # Get top cves
    top_cve_table = top_cves[["cve_id", "summary"]]
    top_cve_table["summary"] = top_cve_table["summary"].str[:400]
    top_cve_table = top_cve_table.rename(
        columns={"cve_id": "CVE", "summary": "Description"}
    )

    return (
        dark_web_mentions,
        alerts,
        darkWeb,
        dark_web_date,
        dark_web_sites,
        alerts_threats,
        dark_web_bad_actors,
        dark_web_tags,
        dark_web_content,
        alerts_exec,
        dark_web_most_act,
        top_cves,
        top_cve_table,
    )


def generate_metrics(datestring, org_uid):
    """Gather all data points for each metric type."""
    # Format start_date and end_date
    end_date = datetime.strptime(datestring, "%Y-%m-%d").date()
    if end_date.day == 15:
        start_date = datetime(end_date.year, end_date.month, 1)
    else:
        start_date = datetime(end_date.year, end_date.month, 16)
    idx = pd.date_range(start_date, end_date).strftime("%m/%d/%Y")

    # Generate metrics from each dataframe
    (
        creds,
        breach,
        pw_creds,
        ce_date_df,
        breach_det_df,
        creds_attach,
        creds_attach2,
        breach_appendix,
    ) = credential_metrics(start_date, end_date, org_uid)

    domain_masq, domain_sum, domain_count, utlds = domain_metrics(
        idx, org_uid, start_date, end_date
    )
    (
        insecure_df,
        vulns_df,
        output_df,
        pro_count,
        unverif_df,
        risky_assets,
        verif_vulns,
        verif_vulns_summary,
        riskyPortsCount,
        verifVulns,
        unverifVulnAssets,
    ) = malware_vuln_metrics(org_uid, start_date, end_date)

    (
        dark_web_mentions,
        alerts,
        darkWeb,
        dark_web_date,
        dark_web_sites,
        alerts_threats,
        dark_web_bad_actors,
        dark_web_tags,
        dark_web_content,
        alerts_exec,
        dark_web_most_act,
        top_cves,
        top_cve_table,
    ) = mention_metrics(org_uid, start_date, end_date)

    return (
        creds,
        breach,
        pw_creds,
        ce_date_df,
        breach_det_df,
        creds_attach,
        creds_attach2,
        breach_appendix,
        domain_masq,
        domain_sum,
        domain_count,
        utlds,
        insecure_df,
        vulns_df,
        output_df,
        pro_count,
        unverif_df,
        risky_assets,
        verif_vulns,
        verif_vulns_summary,
        riskyPortsCount,
        verifVulns,
        unverifVulnAssets,
        dark_web_mentions,
        alerts,
        darkWeb,
        dark_web_date,
        dark_web_sites,
        alerts_threats,
        dark_web_bad_actors,
        dark_web_tags,
        dark_web_content,
        alerts_exec,
        dark_web_most_act,
        top_cves,
        top_cve_table,
    )
