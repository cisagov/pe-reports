"""Scripts for importing Sixgill data into PE Postgres database."""

# Standard Python Libraries
import logging

# Third-Party Libraries
import pandas as pd
import requests

from .api import (
    alerts_content,
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
    aliases = df_assets["organization_aliases"].loc["explicit":].tolist()[0]
    return aliases


def all_assets_list(org_id):
    """List an organization's aliases."""
    assets = org_assets(org_id)
    df_assets = pd.DataFrame(assets)
    aliases = df_assets["organization_aliases"].loc["explicit":].tolist()[0]
    domain_names = df_assets["domain_names"].loc["explicit":].tolist()[0]
    ips = df_assets["ip_addresses"].loc["explicit":].tolist()[0]
    assets = aliases + domain_names + ips
    return assets


def root_domains(org_id):
    """Get root domains."""
    assets = org_assets(org_id)
    df_assets = pd.DataFrame(assets)
    root_domains = df_assets["domain_names"].loc["explicit":].tolist()[0]
    return root_domains


def mentions(date, aliases):
    """Pull dark web mentions data for an organization."""
    mentions = ""
    for mention in aliases:
        mentions += '"' + mention + '"' + ","
    mentions = mentions[:-1]
    query = "date:" + date + " AND NOT site:telegram AND NOT site:forum_4chan AND NOT site:reddit AND NOT site:forum_elhacker AND " + "(" + str(mentions) + ")"
    logging.info("Query:")
    logging.info(query)
    count = 1
    while count < 7:
        try:
            logging.info("Intel post try #%s", count)
            resp = intel_post(query, frm=0, scroll=False, result_size=1)
            break
        except Exception:
            logging.info("Error. Trying intel_post again...")
            count += 1
            continue
    count_total = resp["total_intel_items"]
    logging.info("Total Mentions: %s", count_total)

    i = 0
    all_mentions = []
    if count_total < 10000:
        while i < count_total:
            # Recommended "from" and "result_size" is 50. The maximum is 400.
            resp = intel_post(query, frm=i, scroll=False, result_size=200)
            i += 200
            logging.info("Getting %s of %s....", i, count_total)
            intel_items = resp["intel_items"]
            df_mentions = pd.DataFrame.from_dict(intel_items)
            all_mentions.append(df_mentions)
            df_all_mentions = pd.concat(all_mentions).reset_index(drop=True)
    else:
        while i < count_total:
            # Recommended "from" and "result_size" is 50. The maximum is 400.
            resp = intel_post(query, frm=i, scroll=True, result_size=200)
            i += 200
            logging.info("Getting %s of %s....", i, count_total)
            intel_items = resp["intel_items"]
            df_mentions = pd.DataFrame.from_dict(intel_items)
            all_mentions.append(df_mentions)
            df_all_mentions = pd.concat(all_mentions).reset_index(drop=True)

    return df_all_mentions


def alerts(org_id):
    """Get actionable alerts for an organization."""
    count = alerts_count(org_id)
    count_total = count["total"]
    logging.info("Total Alerts: %s", count_total)

    # Recommended "fetch_size" is 25. The maximum is 400.
    fetch_size = 25
    all_alerts = []

    for offset in range(0, count_total, fetch_size):
        resp = alerts_list(org_id, fetch_size, offset).json()
        df_alerts = pd.DataFrame.from_dict(resp)
        all_alerts.append(df_alerts)
        df_all_alerts = pd.concat(all_alerts).reset_index(drop=True)

    # Fetch the full content of each alert
    # for i, r in df_all_alerts.iterrows():
    #     print(r["id"])
    #     content = alerts_content(org_id, r["id"])
    #     df_all_alerts.at[i, "content"] = content

    return df_all_alerts


def get_alerts_content(organization_id, alert_id):
    """Get alert content snippet."""
    content = alerts_content(organization_id, alert_id)
    org_assets = all_assets_list(organization_id)
    asset_mentioned = ""
    snip = ""
    for asset in org_assets:
        if asset in content:
            index = content.index(asset)
            snip = content[(index - 100) : (index + len(asset) + 100)]
            snip = "..." + snip + "..."
            asset_mentioned = asset
    return snip, asset_mentioned


def top_cves(size):
    """Top 10 CVEs mentioned in the dark web."""
    resp = dve_top_cves(size)
    return pd.DataFrame(resp)


def cve_summary(cveid):
    """Get CVE summary data."""
    url = f"https://cve.circl.lu/api/cve/{cveid}"
    return requests.get(url).json()


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
