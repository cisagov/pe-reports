"""Cybersixgill API calls."""
# Standard Python Libraries
import json
import logging
import time

# Third-Party Libraries
import pandas as pd
import requests

# cisagov Libraries
from pe_source.data.pe_db.config import cybersix_token

LOGGER = logging.getLogger(__name__)


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
            LOGGER.info("Error. Trying query post again...")
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
        LOGGER.error("Failed getting content snip: %s", e)
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


def setNewCSGOrg(newOrgName, orgAliases, orgDomainNames, orgIP, orgExecs):
    """Set a new stakeholder name in CSG."""
    newOrganization = json.dumps(
        {
            "name": f"{newOrgName}",
            "organization_commercial_category": "customer",
            "countries": ["worldwide"],
            "industries": ["Government"],
        }
    )
    url = "https://api.cybersixgill.com/multi-tenant/organization"

    headers = {
        "Content-Type": "application/json",
        "Cache-Control": "no-cache",
        "Authorization": f"Bearer {cybersix_token()}",
    }

    response = requests.post(url, headers=headers, data=newOrganization).json()

    newOrgID = response["id"]

    if newOrgID:
        LOGGER.info("A new org_id was created: %s", newOrgID)
        setOrganizationUsers(newOrgID)
        setOrganizationDetails(newOrgID, orgAliases, orgDomainNames, orgIP, orgExecs)

    return response


def setOrganizationUsers(org_id):
    """Set CSG user permissions at new stakeholder."""
    role1 = "5d23342df5feaf006a8a8929"
    role2 = "5d23342df5feaf006a8a8927"
    id_role1 = "610017c216948d7efa077a52"
    csg_role_id = "role_id"
    csg_user_id = "user_id"

    for user in getUserInfo():
        userrole = user[csg_role_id]
        user_id = user[csg_user_id]

        if (
            (userrole == role1)
            and (user_id != id_role1)
            or userrole == role2
            and user_id != id_role1
        ):

            url = (
                f"https://api.cybersixgill.com/multi-tenant/organization/"
                f"{org_id}/user/{user_id}?role_id={userrole}"
            )

            headers = {
                "Content-Type": "application/json",
                "Cache-Control": "no-cache",
                "Authorization": f"Bearer {cybersix_token()}",
            }

            response = requests.post(url, headers=headers).json()


def setOrganizationDetails(org_id, orgAliases, orgDomain, orgIP, orgExecs):
    """Set stakeholder details at newly created.

    stakeholder at CSG portal via API.
    """
    newOrganizationDetails = json.dumps(
        {
            "organization_aliases": {"explicit": orgAliases},
            "domain_names": {"explicit": orgDomain},
            "ip_addresses": {"explicit": orgIP},
            "executives": {"explicit": orgExecs},
        }
    )
    url = f"https://api.cybersixgill.com/multi-tenant/" f"organization/{org_id}/assets"

    headers = {
        "Content-Type": "application/json",
        "Cache-Control": "no-cache",
        "Authorization": f"Bearer {cybersix_token()}",
    }

    response = requests.put(url, headers=headers, data=newOrganizationDetails).json()
    LOGGER.info("The response is %s", response)


def getUserInfo():
    """Get all organization details from Cybersixgill via API."""
    url = "https://api.cybersixgill.com/multi-tenant/organization"

    headers = {
        "Content-Type": "application/json",
        "Cache-Control": "no-cache",
        "Authorization": f"Bearer {cybersix_token()}",
    }

    response = requests.get(url, headers=headers).json()

    userInfo = response[1]["assigned_users"]
    return userInfo


def get_bulk_cve_resp(cve_list):
    """
    Make API call to retrieve the corresponding info for a list of CVE names (10 max).

    Args:
        cve_list: list of cve names (i.e. ['CVE-2022-123', 'CVE-2022-456'...])

    Returns:
        Raw API response for CVE list

    """
    c6g_url = "https://api.cybersixgill.com/dve_enrich/enrich"
    auth = cybersix_token()
    headers = {
        "Content-Type": "application/json",
        "Cache-Control": "no-cache",
        "Authorization": "Bearer " + auth,
    }
    body = {
        "filters": {"ids": cve_list},
        "results_size": len(cve_list),
        "from_index": 0,
    }
    # Make API call for specified CVE list
    resp = None
    while resp is None:
        try:
            resp = requests.post(c6g_url, headers=headers, json=body).json()
        except:
            pass

    # Return response
    return resp
