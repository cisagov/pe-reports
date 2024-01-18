"""Scripts for importing Sixgill data into PE Postgres database."""

# Standard Python Libraries
import logging
import time

# Third-Party Libraries
import pandas as pd
import requests

# cisagov Libraries
from pe_source.data.pe_db.config import cybersix_token
from .api import (
    alerts_content,
    alerts_count,
    alerts_list,
    credential_auth,
    dve_top_cves,
    get_bulk_cve_resp,
    intel_post,
    org_assets,
)

# Setup logging
LOGGER = logging.getLogger(__name__)


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


def mentions(date, aliases, soc_media_included=False):
    """Pull dark web mentions data for an organization."""
    token = cybersix_token()
    # Build the query using the org's aliases
    mentions = ""
    for mention in aliases:
        mentions += '"' + mention + '"' + ","
    mentions = mentions[:-1]
    if soc_media_included:
        query = "date:" + date + " AND " + "(" + str(mentions) + ")"
    else:
        query = (
            "date:"
            + date
            + " AND "
            + "("
            + str(mentions)
            + """)
                NOT site:(twitter, Twitter, reddit, Reddit, Parler, parler,
                linkedin, Linkedin, discord, forum_discord, raddle, telegram,
                jabber, ICQ, icq, mastodon)"""
        )
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
    token = cybersix_token()
    count = alerts_count(token, org_id)
    LOGGER.info(count)
    count_total = count["total"]
    LOGGER.info("Total Alerts: %s", count_total)
    # Recommended "fetch_size" is 25. The maximum is 400.
    fetch_size = 25
    all_alerts = []

    for offset in range(0, count_total, fetch_size):
        try:
            resp = alerts_list(token, org_id, fetch_size, offset).json()
            df_alerts = pd.DataFrame.from_dict(resp)
            all_alerts.append(df_alerts)
            df_all_alerts = pd.concat(all_alerts).reset_index(drop=True)
        except Exception as e:
            print(e)
            print("HAD TO CONTINUE THROUGH ALERT CHUNK")
            continue
    # Fetch the full content of each alert
    # for i, r in df_all_alerts.iterrows():
    #     print(r["id"])
    #     content = alerts_content(org_id, r["id"])
    #     df_all_alerts.at[i, "content"] = content
    return df_all_alerts


def get_alerts_content(organization_id, alert_id, org_assets_dict):
    """Get alert content snippet."""
    token = cybersix_token()
    asset_mentioned = ""
    snip = ""
    asset_type = ""
    content = alerts_content(token, organization_id, alert_id)
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
    resp = dve_top_cves()
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
        print(len(resp))
    resp = pd.DataFrame(resp)
    df = resp.drop_duplicates(
        subset=["email", "breach_name"], keep="first"
    ).reset_index(drop=True)
    return df


def extract_bulk_cve_info(cve_list):
    """
    Make API call to C6G and retrieve/extract relevant info for a list of CVE names (10 max).

    Args:
        cve_list: list of cve names (i.e. ['CVE-2022-123', 'CVE-2022-456'...])

    Returns:
        A dataframe with the name and all relevant info for the CVEs listed
    """
    # Call get_bulk_cve_info() function to get response
    resp = get_bulk_cve_resp(cve_list)
    # Check if there was a good response
    if resp is None:
        # If no response, return empty dataframe
        return pd.DataFrame()
    else:
        # Proceed if there is a response
        resp_list = resp.get("objects")
        # Dataframe to hold finalized data
        resp_df = pd.DataFrame()
        # For each cve in api response, extract data
        for i in range(0, len(resp_list)):
            # CVE name
            cve_name = resp_list[i].get("name")
            # CVSS 2.0 info
            cvss_2_info = resp_list[i].get("x_sixgill_info").get("nvd").get("v2")
            if cvss_2_info is not None:
                cvss_2_0 = cvss_2_info.get("current")
                cvss_2_0_sev = cvss_2_info.get("severity")
                cvss_2_0_vec = cvss_2_info.get("vector")
            else:
                [cvss_2_0, cvss_2_0_sev, cvss_2_0_vec] = [None, None, None]
            # CVSS 3.0 info
            cvss_3_info = resp_list[i].get("x_sixgill_info").get("nvd").get("v3")
            if cvss_3_info is not None:
                cvss_3_0 = cvss_3_info.get("current")
                cvss_3_0_sev = cvss_3_info.get("severity")
                cvss_3_0_vec = cvss_3_info.get("vector")
            else:
                [cvss_3_0, cvss_3_0_sev, cvss_3_0_vec] = [None, None, None]
            # DVE info
            dve_info = resp_list[i].get("x_sixgill_info").get("score")
            if dve_info is not None:
                dve_score = dve_info.get("current")
            else:
                dve_score = None

            # Append this row of CVE info to the resp_df
            curr_info = {
                "cve_name": cve_name,
                "cvss_2_0": cvss_2_0,
                "cvss_2_0_severity": cvss_2_0_sev,
                "cvss_2_0_vector": cvss_2_0_vec,
                "cvss_3_0": cvss_3_0,
                "cvss_3_0_severity": cvss_3_0_sev,
                "cvss_3_0_vector": cvss_3_0_vec,
                "dve_score": dve_score,
            }
            resp_df = pd.concat(
                [resp_df, pd.DataFrame(curr_info, index=[0])],
                ignore_index=True,
            )
        # Return dataframe of relevant CVE/CVSS/DVE info
        return resp_df
