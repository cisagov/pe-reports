"""Cybersixgill API calls."""
# Standard Python Libraries
import logging
import time

# Third-Party Libraries
import pandas as pd
import requests

# cisagov Libraries
from pe_source.data.pe_db.config import cybersix_token


def get_sixgill_organizations():
    """Get the list of organizations."""
    url = "https://api.cybersixgill.com/multi-tenant/organization"
    auth = cybersix_token()
    headers = {
        "Content-Type": "application/json",
        "Cache-Control": "no-cache",
        "Authorization": "Bearer " + auth,
    }
    orgs = requests.get(url, headers=headers).json()
    df_orgs = pd.DataFrame(orgs)
    sixgill_dict = df_orgs.set_index("name").agg(list, axis=1).to_dict()
    return sixgill_dict


def org_assets(org_id):
    """Get organization assets."""
    url = f"https://api.cybersixgill.com/multi-tenant/organization/{org_id}/assets"
    auth = cybersix_token()
    headers = {
        "Content-Type": "application/json",
        "Cache-Control": "no-cache",
        "Authorization": "Bearer " + auth,
    }
    payload = {"organization_id": org_id}
    count = 1
    while count < 7:
        try:
            resp = requests.get(url, headers=headers, params=payload).json()
            break
        except Exception:
            time.sleep(5)
            logging.info("Error. Trying query post again...")
            count += 1
            continue
    resp = requests.get(url, headers=headers, params=payload).json()
    return resp


def intel_post(auth, query, frm, scroll, result_size):
    """Get intel items - advanced variation."""
    url = "https://api.cybersixgill.com/intel/intel_items"
    headers = {
        "Content-Type": "application/json",
        "Cache-Control": "no-cache",
        "Authorization": "Bearer " + auth,
    }
    payload = {
        "query": query,
        "partial_content": False,
        "results_size": result_size,
        "scroll": scroll,
        "from": frm,
        "sort": "date",
        "sort_type": "desc",
        "highlight": False,
        "recent_items": False,
        "safe_content_size": True,
    }
    resp = requests.post(url, headers=headers, json=payload).json()
    return resp


def alerts_list(auth, organization_id, fetch_size, offset):
    """Get actionable alerts by ID using organization_id with optional filters."""
    url = "https://api.cybersixgill.com/alerts/actionable-alert"
    headers = {
        "Content-Type": "application/json",
        "Cache-Control": "no-cache",
        "Authorization": "Bearer " + auth,
    }
    payload = {
        "organization_id": organization_id,
        "fetch_size": fetch_size,
        "offset": offset,
    }
    resp = requests.get(url, headers=headers, params=payload)
    return resp


def alerts_count(auth, organization_id):
    """Get the total read and unread actionable alerts by organization."""
    url = "https://api.cybersixgill.com/alerts/actionable_alert/count"
    headers = {
        "Content-Type": "application/json",
        "Cache-Control": "no-cache",
        "Authorization": "Bearer " + auth,
    }
    payload = {"organization_id": organization_id}
    resp = requests.get(url, headers=headers, params=payload).json()
    return resp


def alerts_content(auth, organization_id, alert_id):
    """Get total alert content."""
    url = f"https://api.cybersixgill.com/alerts/actionable_alert_content/{alert_id}"
    headers = {
        "Content-Type": "application/json",
        "Cache-Control": "no-cache",
        "Authorization": "Bearer " + auth,
    }
    payload = {"organization_id": organization_id, "limit": 10000}
    content = requests.get(url, headers=headers, params=payload).json()
    try:
        content = content["content"]["items"][0]
        if "_source" in content:
            content = content["_source"]["content"]
        elif "description" in content:
            content = content["description"]
        else:
            content = ""
    except Exception as e:
        logging.error("Failed getting content snip: %s", e)
        content = ""
    return content


def dve_top_cves(size):
    """Get data about a specific CVE."""
    url = "https://api.cybersixgill.com/dve_enrich/top_cves"
    auth = cybersix_token()
    headers = {
        "Content-Type": "application/x-www-form-urlencoded",
        "Cache-Control": "no-cache",
        "Authorization": "Bearer " + auth,
    }
    payload = {"size": size}
    resp = requests.get(url, headers=headers, params=payload).json()
    return resp


def credential_auth(params):
    """Get data about a specific CVE."""
    url = "https://api.cybersixgill.com/credentials/leaks"
    auth = cybersix_token()
    headers = {
        "Content-Type": "application/json",
        "Cache-Control": "no-cache",
        "Authorization": "Bearer " + auth,
    }
    resp = requests.get(url, headers=headers, params=params).json()
    return resp
