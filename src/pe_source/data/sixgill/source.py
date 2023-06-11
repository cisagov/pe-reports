"""Scripts for importing Sixgill data into PE Postgres database."""

# Standard Python Libraries
import logging
import time

# Third-Party Libraries
import pandas as pd
import requests

# cisagov Libraries
from pe_reports import app
from pe_source.data.pe_db.config import cybersix_token

from .api import (
    alerts_content,
    alerts_count,
    alerts_list,
    credential_auth,
    dve_top_cves,
    intel_post,
    org_assets,
)

LOGGER = app.config["LOGGER"]


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
    alias_dict = dict.fromkeys(aliases, "alias")
    domain_names = df_assets["domain_names"].loc["explicit":].tolist()[0]
    domain_dict = dict.fromkeys(domain_names, "domain")
    ips = df_assets["ip_addresses"].loc["explicit":].tolist()[0]
    ip_dict = dict.fromkeys(ips, "ip")
    assets_dict = {**alias_dict, **domain_dict, **ip_dict}
    return assets_dict


def root_domains(org_id):
    """Get root domains."""
    assets = org_assets(org_id)
    df_assets = pd.DataFrame(assets)
    root_domains = df_assets["domain_names"].loc["explicit":].tolist()[0]
    return root_domains


def mentions(date, aliases):
    """Pull dark web mentions data for an organization."""
    token = cybersix_token()

    # Build the query using the org's aliases
    mentions = ""
    for mention in aliases:
        mentions += '"' + mention + '"' + ","
    mentions = mentions[:-1]
    query = "site:forum_* AND date:" + date + " AND " + "(" + str(mentions) + ")"
    LOGGER.info("Query:")
    LOGGER.info(query)

    # Get the total number of mentions
    count = 1
    while count < 7:
        try:
            LOGGER.info("Total mentions try #%s", count)
            resp = intel_post(token, query, frm=0, scroll=False, result_size=1)
            break
        except Exception:
            LOGGER.info("Error. Trying to get mentions count again...")
            count += 1
            continue
    total_mentions = resp["total_intel_items"]
    LOGGER.info("Total Mentions: %s", total_mentions)

    # Fetch mentions in segments
    # Recommended segment is 50. The maximum is 400.
    i = 0
    segment_size = 100
    smaller_segment_count = 1
    all_mentions = []
    while i < total_mentions:
        # Try to get a mentions segment 3 times
        try_count = 1
        while try_count < 4:
            try:
                # If segment size was decreased, only use for 10 iterations
                if smaller_segment_count == 10:
                    LOGGER.info("Switching back to a segment size of 100.")
                    segment_size = 100
                    smaller_segment_count = 1
                if segment_size <= 10:
                    smaller_segment_count += 1
                # API post
                resp = intel_post(
                    token, query, frm=i, scroll=False, result_size=segment_size
                )
                i += segment_size
                LOGGER.info(
                    "Got %s-%s of %s...",
                    i - segment_size,
                    i,
                    total_mentions,
                )
                intel_items = resp["intel_items"]
                df_mentions = pd.DataFrame.from_dict(intel_items)
                all_mentions.append(df_mentions)
                df_all_mentions = pd.concat(all_mentions).reset_index(drop=True)
                break
            except Exception:
                # Sleep for 2 seconds
                time.sleep(2)
                # If the API post failed 3 times
                if try_count == 3:
                    # If a segment was already decreased to 1, skip the mention
                    if segment_size == 1:
                        LOGGER.critical("Failed 3 times fetching 1 post. Skipping it.")
                        i += segment_size
                        break
                    # Decrease the segment to 10, then if still failing, to 1
                    if segment_size == 10:
                        segment_size = 1
                        smaller_segment_count = 1
                    else:
                        segment_size = 10
                    LOGGER.error(
                        "Failed 3 times. Switching to a segment size of %s",
                        segment_size,
                    )
                    try_count = 1
                    continue
                LOGGER.error("Try %s/3 failed.", try_count)
                try_count += 1
    return df_all_mentions


def alerts(org_id):
    """Get actionable alerts for an organization."""
    count = alerts_count(org_id)
    count_total = count["total"]
    LOGGER.info("Total Alerts: %s", count_total)

    # Recommended "fetch_size" is 25. The maximum is 400.
    fetch_size = 25
    all_alerts = []

    for offset in range(0, count_total, fetch_size):
        resp = alerts_list(org_id, fetch_size, offset).json()
        df_alerts = pd.DataFrame.from_dict(resp)
        all_alerts.append(df_alerts)
        df_all_alerts = pd.concat(all_alerts).reset_index(drop=True)

    return df_all_alerts


def get_alerts_content(organization_id, alert_id, org_assets_dict):
    """Get alert content snippet."""
    asset_mentioned = ""
    snip = ""
    asset_type = ""
    content = alerts_content(organization_id, alert_id)
    if content:
        for asset, type in org_assets_dict.items():
            if asset in content:
                index = content.index(asset)
                snip = content[(index - 100) : (index + len(asset) + 100)]
                snip = "..." + snip + "..."
                asset_mentioned = asset
                asset_type = type
                LOGGER.info("Asset mentioned: %s", asset_mentioned)
    return snip, asset_mentioned, asset_type


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
