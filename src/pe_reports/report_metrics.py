"""Generate metrics for each page."""
# Standard Python Libraries
from datetime import datetime

# Third-Party Libraries
import pandas as pd
from pe_db.query import (
    close,
    connect,
    query_darkweb,
    query_darkweb_cves,
    query_domMasq,
    query_hibp_view,
    query_shodan,
)


def credential_metrics(start_date, end_date, org_uid):
    """Calculate compromised credentials metrics and return variables and dataframes."""
    conn = connect()
    view_df = query_hibp_view(conn, org_uid, start_date, end_date)
    hibp_df = view_df[["added_date", "password_included", "email"]]
    hibp_df["added_date"] = pd.to_datetime(hibp_df["added_date"]).dt.date
    # hibp_df = hibp_df.append(c6_df, ignore_index=True)
    creds = len(hibp_df)
    pw_creds = len(hibp_df[hibp_df["password_included"]])

    hibp_df = hibp_df.groupby(["added_date", "password_included"], as_index=False).agg(
        {"email": ["count"]}
    )
    idx = pd.date_range(start_date, end_date)
    hibp_df.columns = hibp_df.columns.droplevel(1)
    hibp_df = (
        hibp_df.pivot(index="added_date", columns="password_included", values="email")
        .fillna(0)
        .reset_index()
        .rename_axis(None)
    )
    hibp_df.columns.name = None
    hibp_df = (
        hibp_df.set_index("added_date")
        .reindex(idx)
        .fillna(0.0)
        .rename_axis("added_date")
    )
    hibp_df["added_date"] = hibp_df.index
    hibp_df["added_date"] = hibp_df["added_date"].dt.strftime("%m/%d/%y")
    hibp_df = hibp_df.set_index("added_date")

    ce_date_df = hibp_df.rename(
        columns={True: "Passwords Included", False: "No Password"}
    )
    if len(ce_date_df.columns) == 0:
        ce_date_df["Passwords Included"] = 0

    print(ce_date_df)

    breach_df = view_df.groupby(
        [
            "breach_name",
            "modified_date",
            "description",
            "breach_date",
            "added_date",
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
        breach_appendix,
    )


def domain_metrics(idx, org_uid, start_date, end_date):
    """Calculate domain metrics and return variables and dataframes."""
    # Get domain masq data from PE database
    conn = connect()
    df = query_domMasq(conn, org_uid, start_date, end_date)

    print(df)

    domain_sum = df[
        ["domain_permutation", "ipv4", "ipv6", "mail_server", "name_server", "fuzzer"]
    ]
    df["tld"] = df["domain_permutation"].str.split(".").str[-1].str.split("/").str[0]
    utlds = len(df["tld"].unique())
    print(utlds)
    domain_count = len(domain_sum.index)
    print(domain_count)
    domain_sum = domain_sum[:25]
    print(domain_sum)
    close(conn)

    return domain_sum, domain_count, utlds


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
    # output_df = query_shodan(conn, org_uid, start_date, end_date, "shodan_assets")
    close(conn)
    # Table: Insecure protocols
    insecure = insecure_df[insecure_df["type"] == "Insecure Protocol"]
    insecure = insecure[
        (insecure["protocol"] != "http") & (insecure["protocol"] != "smtp")
    ]
    risky_assets = insecure[["ip", "protocol"]].drop_duplicates(keep="first")
    # print(risky_assets)

    # Horizontal bar: insecure protocol count
    pro_count = risky_assets.groupby(["protocol"], as_index=False)["protocol"].agg(
        {"id_count": "count"}
    )
    # print(pro_count)
    # Total Open Ports with Insecure protocols
    riskyPortsCount = pro_count["id_count"].sum()
    # print(riskyPortsCount)
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
    # print(verifVulns)
    # print(verif_vulns)
    # print(verif_vulns_summary)
    # Horizaontal Bar: # of unverified CVE's for each IP (TOP 15)

    unverif_df = insecure_df[insecure_df["type"] != "Insecure Protocol"]
    print(unverif_df.columns)
    print(unverif_df[["potential_vulns", "ip"]])
    unverif_df = unverif_df.copy()
    unverif_df["potential_vulns"] = (
        unverif_df["potential_vulns"]
        .sort_values()
        .apply(lambda x: sorted(x))
        # .reset_index(drop=True)
    )

    unverif_df["potential_vulns"] = unverif_df["potential_vulns"].astype("str")
    print(unverif_df)
    unverif_df = (
        unverif_df[["potential_vulns", "ip"]]
        .drop_duplicates(keep="first")
        .reset_index(drop=True)
    )
    # print(unverif_df)
    # print(unverif_df[["potential_vulns", "ip"]])
    unverif_df["count"] = unverif_df["potential_vulns"].str.split(",").str.len()
    unverif_df = unverif_df[["ip", "count"]]
    # unverifVulns = unverif_df["count"].sum()
    print(unverif_df)
    unverif_df = unverif_df.sort_values(by=["count"], ascending=False)
    unverifVulnAssets = len(unverif_df.index)
    unverif_df = unverif_df[:15].reset_index(drop=True)
    # print(unverifVulns)
    # print(unverif_df)
    return (
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
    close(conn)

    # Get total number of Dark Web mentions
    darkWeb = len(dark_web_mentions.index)

    # Get dark web mentions by date
    dark_web_date = dark_web_mentions[["date"]]
    dark_web_date = (
        dark_web_date.groupby(["date"])["date"].count().reset_index(name="Count")
    )

    # Get mentions by dark web sites (top 10)
    dark_web_sites = dark_web_mentions[["site"]]
    dark_web_sites = (
        dark_web_sites.groupby(["site"])["site"]
        .count()
        .nlargest(10)
        .reset_index(name="count")
    )

    # Get alert threats
    alerts_threats = alerts[["site", "threats"]]
    alerts_threats = alerts_threats[alerts_threats["site"] != "NaN"]
    alerts_threats = alerts_threats[alerts_threats["site"] != ""]
    alerts_threats = (
        alerts_threats.groupby(["site", "threats"])["threats"]
        .count()
        .nlargest(10)
        .reset_index(name="Events")
    )
    alerts_threats["threats"] = alerts_threats["threats"].str.strip("{}")

    # Get dark web bad actors
    dark_web_bad_actors = dark_web_mentions[["creator", "rep_grade"]]
    dark_web_bad_actors = dark_web_bad_actors.groupby("creator", as_index=False).max()
    dark_web_bad_actors = dark_web_bad_actors.sort_values(
        by=["rep_grade"], ascending=False
    )[:10]
    dark_web_bad_actors["rep_grade"] = (
        dark_web_bad_actors["rep_grade"].astype(float).round(decimals=3)
    )

    # Get dark web notable tags
    dark_web_tags = dark_web_mentions[["tags"]]
    dark_web_tags = dark_web_tags[dark_web_tags["tags"] != "NaN"]
    dark_web_tags = (
        dark_web_tags.groupby(["tags"])["tags"]
        .count()
        .nlargest(10)
        .reset_index(name="Events")
    )
    dark_web_tags["tags"] = dark_web_tags["tags"].str.strip("{}")

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

    # Get most active posts
    dark_web_most_act = dark_web_mentions[["comments_count", "title", "content"]]
    dark_web_most_act = dark_web_most_act[dark_web_most_act["comments_count"] != "NaN"]
    dark_web_most_act = dark_web_most_act.sort_values(
        by="comments_count", ascending=False
    )
    dark_web_most_act = dark_web_most_act.rename(columns={"comments_count": "Events"})
    dark_web_most_act = dark_web_most_act[:5]
    dark_web_most_act["Events"] = dark_web_most_act["Events"].astype(float).astype(int)

    # Get top cves
    top_cves = top_cves[["cve_id", "nvd_base_score"]]

    return (
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
        breach_appendix,
    ) = credential_metrics(start_date, end_date, org_uid)

    domain_sum, domain_count, utlds = domain_metrics(idx, org_uid, start_date, end_date)
    (
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
    ) = mention_metrics(org_uid, start_date, end_date)

    return (
        creds,
        breach,
        pw_creds,
        ce_date_df,
        breach_det_df,
        creds_attach,
        breach_appendix,
        domain_sum,
        domain_count,
        utlds,
        pro_count,
        unverif_df,
        risky_assets,
        verif_vulns,
        verif_vulns_summary,
        riskyPortsCount,
        verifVulns,
        unverifVulnAssets,
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
    )
