"""Cybersixgill API calls."""
# Third-Party Libraries
import pandas as pd
import requests

from .config import token


def get_sixgill_organizations():
    """Get the list of organizations."""
    url = "https://api.cybersixgill.com/multi-tenant/organization"
    auth = token()
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
    auth = token()
    headers = {
        "Content-Type": "application/json",
        "Cache-Control": "no-cache",
        "Authorization": "Bearer " + auth,
    }
    payload = {"organization_id": org_id}
    resp = requests.get(url, headers=headers, params=payload).json()
    return resp


def intel_post(query, frm, scroll, result_size):
    """Get intel items - advanced variation."""
    url = "https://api.cybersixgill.com/intel/intel_items"
    auth = token()
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


def alerts_list(organization_id, fetch_size, offset):
    """Get actionable alerts by ID using organization_id with optional filters."""
    url = "https://api.cybersixgill.com/alerts/actionable-alert"
    auth = token()
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


def alerts_count(organization_id):
    """Get the total read and unread actionable alerts by organization."""
    url = "https://api.cybersixgill.com/alerts/actionable_alert/count"
    auth = token()
    headers = {
        "Content-Type": "application/json",
        "Cache-Control": "no-cache",
        "Authorization": "Bearer " + auth,
    }
    payload = {"organization_id": organization_id}
    resp = requests.get(url, headers=headers, params=payload).json()
    return resp


def alerts_content(organization_id, alert_id):
    """Get an alert's full content."""
    url = f"https://api.cybersixgill.com/alerts/actionable_alert_content/{alert_id}"
    auth = token()
    headers = {
        "Content-Type": "application/json",
        "Cache-Control": "no-cache",
        "Authorization": "Bearer " + auth,
    }
    payload = {"organization_id": organization_id, "limit": 10000}
    resp = requests.get(url, headers=headers, params=payload).json()
    return str(resp["content"])


def dve_top_cves(size):
    """Get data about a specific CVE."""
    url = "https://api.cybersixgill.com/dve_enrich/top_cves"
    auth = token()
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
    auth = token()
    headers = {
        "Content-Type": "application/json",
        "Cache-Control": "no-cache",
        "Authorization": "Bearer " + auth,
    }
    resp = requests.get(url, headers=headers, params=params).json()
    return resp
