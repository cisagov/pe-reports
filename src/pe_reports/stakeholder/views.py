"""Classes and associated functions that render the UI app pages."""

# Standard Python Libraries
from datetime import date
from ipaddress import ip_address, ip_network
import json
import logging
import os
import socket

# Third-Party Libraries
from flask import Blueprint, flash, redirect, render_template, url_for
import psycopg2
import psycopg2.extras
import requests

# cisagov Libraries
from pe_reports.data.config import config
from pe_reports.stakeholder.forms import InfoFormExternal

LOGGER = logging.getLogger(__name__)

# CSG credentials
API_Client_ID = os.getenv("CSGUSER")
API_Client_secret = os.environ.get("CSGSECRET")
API_WHOIS = os.environ.get("WHOIS_VAR")

conn = None
cursor = None
thedateToday = date.today().strftime("%Y-%m-%d")


def getToken():
    """Get authorization token from Cybersixgill (CSG)."""
    d = {
        "grant_type": "client_credentials",
        "client_id": f"{API_Client_ID}",
        "client_secret": f"{API_Client_secret}",
    }
    r = requests.post("https://api.cybersixgill.com/auth/token", data=d)
    r = r.text.split(":")
    r = r[1].lstrip('"').rsplit('"')[0]
    return r


def getAgencies(org_name):
    """Get all agency names from P&E database."""
    global conn, cursor

    try:
        params = config()

        conn = psycopg2.connect(**params)

        if conn:
            LOGGER.info(
                "There was a connection made to"
                "the database and the query was executed."
            )

            cursor = conn.cursor(cursor_factory=psycopg2.extras.DictCursor)

            query = "select organizations_uid,name from"
            " organizations where name='{}';"

            cursor.execute(query.format(org_name))

            result = cursor.fetchall()
            resultDict = {}

            for row in result:
                # row[0] = org UUID
                # row[1] = org name
                resultDict[f"{row[0]}"] = f"{row[1]}"
            return resultDict

    except (Exception, psycopg2.DatabaseError) as err:
        LOGGER.error("There was a problem logging into the psycopg database %s", err)
    finally:
        if conn is not None:
            cursor.close()
            conn.close()
            LOGGER.info("The connection/query was completed and closed.")

            return resultDict


def getRootID(org_UUID):
    """Get all root domain names from P&E database."""
    global conn, cursor
    resultDict = {}
    try:
        params = config()

        conn = psycopg2.connect(**params)

        if conn:
            LOGGER.info(
                "There was a connection made to the database and the query was executed "
            )

            cursor = conn.cursor(cursor_factory=psycopg2.extras.DictCursor)
            query = "select root_domain_uid, organization_name from"
            " root_domains where organizations_uid='{}';"

            cursor.execute(query.format(org_UUID))

            result = cursor.fetchall()

            for row in result:
                # row[0] = root UUID
                # row[1] = org name
                resultDict[f"{row[1]}"] = f"{row[0]}"
            return resultDict

    except (Exception, psycopg2.DatabaseError) as err:
        LOGGER.error("There was a problem logging into the psycopg database %s", err)
    finally:
        if conn is not None:
            cursor.close()
            conn.close()
            LOGGER.info("The connection/query was completed and closed.")

            return resultDict


def setStakeholder(customer):
    """Insert customer into the P&E reports database."""
    global conn, cursor

    try:
        LOGGER.info("Starting insert into database...")

        params = config()

        conn = psycopg2.connect(**params)

        if conn:

            LOGGER.info(
                "There was a connection made to "
                "the database and the query was executed "
            )

            cursor = conn.cursor()

            cursor.execute(f"insert into organizations(name)" f"values('{customer}')")

            return True

    except (Exception, psycopg2.DatabaseError) as err:
        LOGGER.error("There was a problem logging into the psycopg database %s", err)
        return False
    finally:
        if conn is not None:
            conn.commit()
            cursor.close()
            conn.close()
            LOGGER.info("The connection/query was completed and closed.")


def setCustRootDomain(customer, rootdomain, orgUUID):
    """Insert customer root domain into the PE-Reports database."""
    global conn, cursor

    try:
        LOGGER.info("Starting insert into database...")

        params = config()

        conn = psycopg2.connect(**params)

        if conn:

            LOGGER.info(
                "There was a connection made to "
                "the database and the query was executed "
            )

            cursor = conn.cursor()

            cursor.execute(
                f"insert into root_domains("
                f"organizations_uid,"
                f"organization_name,"
                f" root_domain)"
                f"values('{orgUUID}', '{customer}','{rootdomain}');"
            )
            return True

    except (Exception, psycopg2.DatabaseError) as err:
        LOGGER.error("There was a problem logging into the psycopg database %s", err)
        return False
    finally:
        if conn is not None:
            conn.commit()
            cursor.close()
            conn.close()
            LOGGER.info("The connection/query was completed and closed.")


def setCustSubDomain(subdomain, rootUUID, rootname):
    """Insert customer into the PE-Reports database."""
    global conn, cursor

    try:

        LOGGER.info("Starting insert into database...")

        params = config()

        conn = psycopg2.connect(**params)

        if conn:

            LOGGER.info(
                "There was a connection made to "
                "the database and the query to "
                "insert the subdomains was executed "
            )

            cursor = conn.cursor()

            for sub in subdomain:
                cursor.execute(
                    f"insert into sub_domains("
                    f"sub_domain,"
                    f"root_domain_uid,"
                    f" root_domain)"
                    f"values('{sub}',"
                    f" '{rootUUID}',"
                    f"'{rootname}');"
                )
            return True

    except (Exception, psycopg2.DatabaseError) as err:
        LOGGER.error("There was a problem logging into the psycopg database %s", err)
        return False
    finally:
        if conn is not None:
            conn.commit()
            cursor.close()
            conn.close()
            LOGGER.info("The connection/query was completed and closed.")


def setCustomerExternalCSG(
    customer, customerIP, customerRootDomain, customerSubDomain, customerExecutives
):
    """Insert customer not in cyhyDB into the PE-Reports database."""
    global conn, cursor

    iplist = []
    domainlist = []
    try:
        LOGGER.info("Starting insert into database...")

        params = config()

        conn = psycopg2.connect(**params)

        if conn:

            LOGGER.info(
                "There was a connection made to"
                " the database and the query was executed "
            )

            cursor = conn.cursor()

            for ip in customerIP:
                iplist.append(ip)

                cursor.execute(
                    f"insert into organizations(domain_name,"
                    f" domain_ip,"
                    f" date_saved) "
                    f"values('{customer}',"
                    f" '{ip}',"
                    f"'{thedateToday}');"
                )
            for domain in customerRootDomain:
                domainlist.append(domain)
                cursor.execute(
                    f"insert into domain_assets(domain_name,"
                    f" domain_ip,"
                    f" date_saved) "
                    f"values('{customer}',"
                    f" '{ip}', '{thedateToday}');"
                )

    except (Exception, psycopg2.DatabaseError) as err:
        LOGGER.error("There was a problem logging into the psycopg database %s", err)
    finally:
        if conn is not None:
            conn.commit()
            cursor.close()
            conn.close()
            LOGGER.info("The connection/query was completed and closed.")

    return iplist


def getSubdomain(domain):
    """Get all sub-domains from passed in root domain."""
    allsubs = []

    url = "https://domains-subdomains-discovery.whoisxmlapi.com/api/v1"
    payload = json.dumps(
        {
            "apiKey": f"{API_WHOIS}",
            "domains": {"include": [f"{domain}"]},
            "subdomains": {"include": ["*"], "exclude": []},
        }
    )
    headers = {"Content-Type": "application/json"}
    response = requests.request("POST", url, headers=headers, data=payload)
    data = response.json()

    subdomains = data["domainsList"]
    LOGGER.info(subdomains)

    subisolated = ""
    for sub in subdomains:

        if sub != f"www.{domain}":

            LOGGER.info(sub)
            subisolated = sub.rsplit(".")[:-2]
            LOGGER.info(
                "The whole sub is %s and the isolated sub is %s", sub, subisolated
            )
        allsubs.append(subisolated)

    return subdomains, allsubs


def theaddress(domain):
    """Get actual IP address of domain."""
    gettheAddress = ""
    try:
        gettheAddress = socket.gethostbyname(domain)
    except socket.gaierror:
        LOGGER.info("There is a problem with the domain that you selected")

    return gettheAddress


def getallsubdomainIPS(domain):
    """Get a list of IP addresses associated with a subdomain."""
    LOGGER.info("The domain at getallsubdomsinIPS is %s", domain)
    alladdresses = []
    for x in getSubdomain(domain)[0]:
        domainaddress = theaddress(x)
        if domainaddress not in alladdresses and domainaddress != "":
            alladdresses.append(domainaddress)
    return alladdresses


def verifyIPv4(custIP):
    """Verify if parameter is a valid IPv4 IP address."""
    try:
        if ip_address(custIP):
            return True

        else:
            return False

    except ValueError as err:
        LOGGER.error("The address is incorrect, %s", err)
        return False


def verifyCIDR(custIP):
    """Verify if parameter is a valid CIDR block IP address."""
    try:
        if ip_network(custIP):
            return True

        else:
            return False

    except ValueError as err:
        LOGGER.error("The CIDR is incorrect, %s", err)
        return False


def validateIP(custIP):
    """
    Verify IPv4 and CIDR.

    Collect address information into a list that is ready for DB insertion.
    """
    verifiedIP = []
    for the_ip in custIP:
        if verifyCIDR(the_ip) or verifyIPv4(the_ip):
            verifiedIP.append(the_ip)
    return verifiedIP


def getOrganizations():
    """Get all organization details from Cybersixgill via API."""
    url = "https://api.cybersixgill.com/multi-tenant/organization"

    headers = {
        "Content-Type": "application/json",
        "Cache-Control": "no-cache",
        "Authorization": f"Bearer {getToken()}",
    }

    response = requests.get(url, headers=headers).json()
    return response


def setNewCSGOrg(newOrgName, orgAliases, orgdomainNames, orgIP, orgExecs):
    """Set a new stakeholder name at CSG."""
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
        "Authorization": f"Bearer {getToken()}",
    }

    response = requests.post(url, headers=headers, data=newOrganization).json()

    newOrgID = response["id"]

    if newOrgID:
        LOGGER.info("A new org_id was created: %s", newOrgID)

        setOrganizationUsers(newOrgID)
        setOrganizationDetails(newOrgID, orgAliases, orgdomainNames, orgIP, orgExecs)

    return response


def setOrganizationUsers(org_id):
    """Set CSG user permissions at new stakeholder."""
    role1 = os.getenv("USERROLE1")
    role2 = os.getenv("USERROLE2")
    id_role1 = os.getenv("USERID")
    csg_role_id = os.getenv("CSGUSERROLE")
    csg_user_id = os.getenv("CSGUSERID")
    for user in getalluserinfo():
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
                "Authorization": f"Bearer {getToken()}",
            }

            response = requests.post(url, headers=headers).json()
            LOGGER.info(response)


def setOrganizationDetails(org_id, orgAliases, orgDomain, orgIP, orgExecs):
    """Set stakeholder details at newly created.

    stakeholder at CSG portal via API.
    """
    LOGGER.info("The following is from setting details")
    LOGGER.info("The org_id is %s", org_id)
    LOGGER.info("The orgAliases is %s", orgAliases)
    LOGGER.info("The orgDomain is %s", orgDomain)
    LOGGER.info("The orgIP is %s", orgIP)
    LOGGER.info("The orgExecs is %s", orgExecs)
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
        "Authorization": f"Bearer {getToken()}",
    }

    response = requests.put(url, headers=headers, data=newOrganizationDetails).json()
    LOGGER.info("The response is %s", response)


def getalluserinfo():
    """Get CSG user permission role information from CSG."""
    userInfo = getOrganizations()[1]["assigned_users"]

    return userInfo


stakeholder_blueprint = Blueprint(
    "stakeholder", __name__, template_folder="templates/stakeholder_UI"
)


@stakeholder_blueprint.route("/stakeholder", methods=["GET", "POST"])
def stakeholder():
    """Process form information, instantiate form and render page template."""
    LOGGER.debug("made it to stakeholder")
    cust = False
    custDomainAliases = False
    custRootDomain = False
    custExecutives = False

    formExternal = InfoFormExternal()

    if formExternal.validate_on_submit():
        LOGGER.debug("Got to the submit validate")
        cust = formExternal.cust.data.upper()
        custDomainAliases = formExternal.custDomainAliases.data.split(",")
        custRootDomain = formExternal.custRootDomain.data.split(",")
        custRootDomainValue = custRootDomain[0]
        custExecutives = formExternal.custExecutives.data.split(",")
        formExternal.cust.data = ""
        formExternal.custDomainAliases = ""
        formExternal.custRootDomain.data = ""
        formExternal.custExecutives.data = ""
        allDomain = getAgencies(cust)
        allSubDomain = getSubdomain(custRootDomainValue)
        allValidIP = getallsubdomainIPS(custRootDomainValue)

        try:

            if cust not in allDomain.values():
                flash(f"You successfully submitted a new customer {cust} ", "success")

                if setStakeholder(cust):
                    LOGGER.info("The customer %s was entered.", cust)
                    allDomain = list(getAgencies(cust).keys())[0]

                    if setCustRootDomain(cust, custRootDomainValue, allDomain):
                        rootUUID = getRootID(allDomain)[cust]

                        LOGGER.info(
                            "The root domain %s was entered at root_domains.",
                            custRootDomainValue,
                        )
                        if allSubDomain:
                            for subdomain in allSubDomain:
                                if setCustSubDomain(subdomain, rootUUID, cust):
                                    LOGGER.info("The subdomains have been entered.")
                                    setNewCSGOrg(
                                        cust,
                                        custDomainAliases,
                                        custRootDomain,
                                        allValidIP,
                                        custExecutives,
                                    )

            else:
                flash(f"The customer {cust} already exists.", "warning")

        except ValueError as e:
            flash(f"The customer IP {e} is not a valid IP, please try again.", "danger")
            return redirect(url_for("stakeholder.stakeholder"))
        return redirect(url_for("stakeholder.stakeholder"))
    return render_template(
        "home_stakeholder.html",
        formExternal=formExternal,
        cust=cust,
        custRootDomain=custRootDomain,
        custExecutives=custExecutives,
        custDomainAliases=custDomainAliases,
    )
