"""Scripts for importing Sixgill data into PE Postgres database."""

# Standard Python Libraries
import logging

# Third-Party Libraries
import pandas as pd
import requests

from .api import (
    alerts_count,
    alerts_list,
    credential_auth,
    dve_top_cves,
    intel_post,
    org_assets,
)


def alias_organization(org_id):
    """List an organization's aliases."""
    assets = org_assets(org_id)
    df_assets = pd.DataFrame(assets)
    # df_assets.reset_index(level=None, drop=True, inplace=True, col_level=0, col_fill="")
    aliases = df_assets["organization_aliases"].loc["explicit":].tolist()[0]
    # df_explicit = df_assets.iloc[[1]]
    # aliases = str(df_explicit["organization_aliases"].item())
    return aliases


def root_domains(org_id):
    """Get root domains."""
    assets = org_assets(org_id)
    df_assets = pd.DataFrame(assets)
    # df_assets.reset_index(level=None, drop=True, inplace=True, col_level=0, col_fill="")
    root_domains = df_assets["domain_names"].loc["explicit":].tolist()[0]
    # df_explicit = df_assets.iloc[[1]]
    # root_domains = str(df_explicit["domain_names"].item())
    return root_domains


def mentions(date, aliases):
    """Pull dark web mentions data for an organization."""
    mentions = ""
    for mention in aliases:
        mentions += '"' + mention + '"' + ","
    mentions = mentions[:-1]
    query = "site:forum_* AND date:" + date + " AND " + "(" + str(mentions) + ")"
    logging.info("Query:")
    logging.info(query)
    count = 0
    while count <= 5:
        try:
            logging.info(f"Intel post try #{count + 1}")
            resp = intel_post(query, frm=0, scroll=False, result_size=1)
            count = 6
        except Exception:
            logging.info("Error. Trying intel_post again...")
            count += 1
            continue
    count_total = resp["total_intel_items"]
    logging.info(f"Total Mentions: {count_total}")

    i = 0
    all_mentions = []
    if count_total < 10000:
        while i < count_total:
            # Recommended "from" and "result_size" is 50. The maximum is 400.
            resp = intel_post(query, frm=i, scroll=False, result_size=200)
            i = i + 200
            logging.info(f"Getting {i} of {count_total}....")
            intel_items = resp["intel_items"]
            df_mentions = pd.DataFrame.from_dict(intel_items)
            all_mentions.append(df_mentions)
            df_all_mentions = pd.concat(all_mentions).reset_index(drop=True)

    else:
        while i < count_total:
            # Recommended "from" and "result_size" is 50. The maximum is 400.
            resp = intel_post(query, frm=i, scroll=True, result_size=400)
            i = i + 400
            logging.info(f"Getting {i} of {count_total}....")
            intel_items = resp["intel_items"]
            df_mentions = pd.DataFrame.from_dict(intel_items)
            all_mentions.append(df_mentions)
            df_all_mentions = pd.concat(all_mentions).reset_index(drop=True)

    return df_all_mentions


def alerts(org_id):
    """Get actionable alerts for an organization."""
    count = alerts_count(org_id)
    count_total = count["total"]
    logging.info(f"Total Alerts: {count_total}")

    # Recommended "fetch_size" is 25. The maximum is 400.
    fetch_size = 25
    all_alerts = []

    for offset in range(0, count_total, fetch_size):
        resp = alerts_list(org_id, fetch_size, offset).json()
        df_alerts = pd.DataFrame.from_dict(resp)
        all_alerts.append(df_alerts)
        df_all_alerts = pd.concat(all_alerts).reset_index(drop=True)

    return df_all_alerts


def top_cves(size):
    """Top 10 CVEs mention in the dark web."""
    resp = dve_top_cves(size)
    df_top_cves = pd.DataFrame(resp)
    return df_top_cves


def cve_summary(cveid):
    """Get CVE summary data."""
    url = f"https://cve.circl.lu/api/cve/{cveid}"
    resp = requests.get(url).json()
    return resp


def creds(domain, from_date, to_date):
    """Get credentials."""
    skip = 0
    params = {
        "domain": domain,
        "from_date": from_date,
        "to_date": to_date,
        "max_results": 100,
        "skip": skip,
    }
    resp = credential_auth(params)
    total_hits = resp["total_results"]
    resp = resp["leaks"]
    while total_hits > len(resp):
        skip += 1
    params["skip"] = skip
    next_resp = credential_auth(params)
    resp = resp + next_resp["leaks"]
    resp = pd.DataFrame(resp)
    df = resp.drop_duplicates(
        subset=["email", "breach_name"], keep="first"
    ).reset_index(drop=True)
    return df
