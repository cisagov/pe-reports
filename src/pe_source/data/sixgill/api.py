"""Cybersixgill API calls."""
# Standard Python Libraries
import json
import logging
import os
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
        logging.info("A new org_id was created: %s", newOrgID)
        setOrganizationUsers(newOrgID)
        setOrganizationDetails(newOrgID, orgAliases, orgDomainNames, orgIP, orgExecs)

    return response


def setOrganizationUsers(org_id):
    """Set CSG user permissions at new stakeholder."""
    role1 = os.getenv("USERROLE1")
    role2 = os.getenv("USERROLE2")
    id_role1 = os.getenv("USERID")
    csg_role_id = os.getenv("CSGUSERROLE")
    csg_user_id = os.getenv("CSGUSERID")

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

            requests.post(url, headers=headers).json()


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
    logging.info("The response is %s", response)


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
