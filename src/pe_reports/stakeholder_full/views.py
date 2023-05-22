"""Classes and associated functions that render the UI app pages."""

# Standard Python Libraries
import datetime
from datetime import date
from ipaddress import ip_address, ip_network
import json
import logging
import os
import re
import socket
import traceback

# Third-Party Libraries
from bs4 import BeautifulSoup
from flask import Blueprint, flash, redirect, render_template, url_for
import nltk
from nltk import pos_tag, word_tokenize
import numpy as np
import pandas as pd
import psycopg2
import psycopg2.extras
import requests
import spacy

# cisagov Libraries
from pe_reports.data.config import config
from pe_reports.data.db_query import execute_values, get_orgs_df
from pe_reports.helpers.enumerate_subs_from_root import (
    enumerate_and_save_subs,
    query_roots,
)
from pe_asm.helpers.fill_cidrs_from_cyhy_assets import fill_cidrs
from pe_asm.helpers.fill_ips_from_cidrs import fill_ips_from_cidrs
from pe_asm.helpers.link_subs_and_ips_from_ips import connect_subs_from_ips
from pe_asm.helpers.link_subs_and_ips_from_subs import connect_ips_from_subs
from pe_asm.helpers.shodan_dedupe import dedupe
from pe_reports.stakeholder_full.forms import InfoFormExternal

# If you are getting errors saying that a "en_core_web_lg" is loaded. Run the command " python -m spacy download en_core_web_trf" but might have to chagne the name fo the spacy model
# nlp = spacy.load("en_core_web_lg")

LOGGER = logging.getLogger(__name__)

# CSG credentials
# TODO: Insert credentials
API_Client_ID = ""
API_Client_secret = ""
API_WHOIS = ""

conn = None
cursor = None
thedateToday = date.today().strftime("%Y-%m-%d")


def getToken():
    """Get authorization token from Cybersixgill (CSG)."""
    logging.info(API_Client_ID)
    logging.info(API_Client_secret)
    d = {
        "grant_type": "client_credentials",
        "client_id": f"{API_Client_ID}",
        "client_secret": f"{API_Client_secret}",
    }
    r = requests.post("https://api.cybersixgill.com/auth/token", data=d)
    logging.info(r)
    r = r.text.split(":")
    r = r[1].lstrip('"').rsplit('"')[0]
    return r


def getAgencies(cyhy_db_id):
    """Get all agency names from P&E database."""
    global conn, cursor

    try:
        params = config()

        conn = psycopg2.connect(**params)

        if conn:
            logging.info(
                "There was a connection made to"
                "the database and the query was executed."
            )

            cursor = conn.cursor(cursor_factory=psycopg2.extras.DictCursor)

            query = """
            select organizations_uid, name
            from organizations
            where cyhy_db_name = %s;"""

            cursor.execute(query, (cyhy_db_id))

            result = cursor.fetchall()
            resultDict = {}

            for row in result:
                # row[0] = org UUID
                # row[1] = org name
                resultDict[f"{row[0]}"] = f"{row[1]}"
            return resultDict

    except (Exception, psycopg2.DatabaseError) as err:
        logging.error("There was a problem logging into the psycopg database %s", err)
    finally:
        if conn is not None:
            cursor.close()
            conn.close()
            logging.info("The connection/query was completed and closed.")

            return resultDict


def set_org_to_report_on(cyhy_db_id):
    """Query cyhy assets."""
    sql = """
    SELECT *
    FROM organizations o
    where o.cyhy_db_name = %(org_id)s
    """
    params = config()
    conn = psycopg2.connect(**params)
    df = pd.read_sql_query(sql, conn, params={"org_id": cyhy_db_id})

    if len(df) < 1:
        logging.error("No org found for that cyhy id")
        return 0

    for org_index, org_row in df.iterrows():
        if org_row["report_on"] == True and org_row["premium_report"] == True:
            continue
        cursor = conn.cursor()
        sql = """UPDATE organizations
                SET report_on = True, premium_report = True
                WHERE organizations_uid = %s"""
        uid = org_row["organizations_uid"]
        cursor.execute(sql, [uid])
        conn.commit()
        cursor.close()
    conn.close()
    return df


def get_data_source_uid(source):
    """Get data source uid."""
    params = config()
    conn = psycopg2.connect(**params)
    cur = conn.cursor()
    sql = """SELECT * FROM data_source WHERE name = '{}'"""
    cur.execute(sql.format(source))
    source = cur.fetchone()[0]
    cur.close()
    cur = conn.cursor()
    # Update last_run in data_source table
    date = datetime.datetime.today().strftime("%Y-%m-%d")
    sql = """update data_source set last_run = '{}'
            where name = '{}';"""
    cur.execute(sql.format(date, source))
    cur.close()
    conn.close()
    return source


def get_cidrs_and_ips(org_uid):
    """Query all cidrs and ips for an organization."""
    params = config()
    conn = psycopg2.connect(**params)
    cur = conn.cursor()
    sql = """SELECT network from cidrs where
        organizations_uid = %s;"""
    cur.execute(sql, [org_uid])
    cidrs = cur.fetchall()
    sql = """
    SELECT i.ip
    FROM ips i
    join ips_subs ip_s on ip_s.ip_hash = i.ip_hash
    join sub_domains sd on sd.sub_domain_uid = ip_s.sub_domain_uid
    join root_domains rd on rd.root_domain_uid = sd.root_domain_uid
    WHERE rd.organizations_uid = %s
    AND i.origin_cidr is null;
    """
    cur.execute(sql, [org_uid])
    ips = cur.fetchall()
    conn.close()
    cidrs_ips = cidrs + ips
    # cidrs_ips = [item for sublist in cidrs_ips for item in sublist]
    cidrs_ips = [x[0] for x in cidrs_ips]
    cidrs_ips = validateIP(cidrs_ips)
    logging.info(cidrs_ips)
    return cidrs_ips


def insert_roots(org, domain_list):
    """Insert root domains into the database."""
    source_uid = get_data_source_uid("P&E")
    roots_list = []
    for domain in domain_list:
        try:
            ip = socket.gethostbyname(domain)
        except Exception:
            ip = np.nan
        root = {
            "organizations_uid": org["organizations_uid"],
            "root_domain": domain,
            "ip_address": ip,
            "data_source_uid": source_uid,
            "enumerate_subs": True,
        }
        roots_list.append(root)

    roots = pd.DataFrame(roots_list)
    logging.info(roots)
    except_clause = """ ON CONFLICT (root_domain, organizations_uid)
    DO NOTHING;"""
    params = config()
    conn = psycopg2.connect(**params)
    execute_values(conn, roots, "public.root_domains", except_clause)


def getRootID(org_UUID):
    """Get all root domain names from P&E database."""
    global conn, cursor
    resultDict = {}
    try:
        params = config()

        conn = psycopg2.connect(**params)

        if conn:
            logging.info(
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
        logging.error("There was a problem logging into the psycopg database %s", err)
    finally:
        if conn is not None:
            cursor.close()
            conn.close()
            logging.info("The connection/query was completed and closed.")

            return resultDict


def setCustomerExternalCSG(
    customer, customerIP, customerRootDomain, customerSubDomain, customerExecutives
):
    """Insert customer not in cyhyDB into the PE-Reports database."""
    global conn, cursor

    iplist = []
    domainlist = []
    try:
        logging.info("Starting insert into database...")

        params = config()

        conn = psycopg2.connect(**params)

        if conn:

            logging.info(
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
        logging.error("There was a problem logging into the psycopg database %s", err)
    finally:
        if conn is not None:
            conn.commit()
            cursor.close()
            conn.close()
            logging.info("The connection/query was completed and closed.")

    return iplist


def theaddress(domain):
    """Get actual IP address of domain."""
    gettheAddress = ""
    try:
        gettheAddress = socket.gethostbyname(domain)
    except socket.gaierror:
        logging.info("There is a problem with the domain that you selected")

    return gettheAddress


def verifyIPv4(custIP):
    """Verify if parameter is a valid IPv4 IP address."""
    try:
        if ip_address(custIP):
            return True

        else:
            return False

    except ValueError as err:
        logging.error("The address is incorrect, %s", err)
        return False


def verifyCIDR(custIP):
    """Verify if parameter is a valid CIDR block IP address."""
    try:
        if ip_network(custIP):
            return True

        else:
            return False

    except ValueError as err:
        logging.error("The CIDR is incorrect, %s", err)
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
        logging.info("A new org_id was created: %s", newOrgID)

        setOrganizationUsers(newOrgID)
        setOrganizationDetails(newOrgID, orgAliases, orgdomainNames, orgIP, orgExecs)

    return response


def setOrganizationUsers(org_id):
    """Set CSG user permissions at new stakeholder."""
    role1 = "5d23342df5feaf006a8a8929"
    role2 = "5d23342df5feaf006a8a8927"
    id_role1 = "610017c216948d7efa077a52"
    csg_role_id = "role_id"
    csg_user_id = "user_id"
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
            # logging.info(response)


def setOrganizationDetails(org_id, orgAliases, orgDomain, orgIP, orgExecs):
    """Set stakeholder details at newly created.

    stakeholder at CSG portal via API.
    """
    logging.info("The following is from setting details")
    logging.info("The org_id is %s", org_id)
    logging.info("The orgAliases is %s", orgAliases)
    logging.info("The orgDomain is %s", orgDomain)
    logging.info("The orgIP is %s", orgIP)
    logging.info("The orgExecs is %s", orgExecs)
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
    logging.info("The response is %s", response)


def getalluserinfo():
    """Get CSG user permission role information from CSG."""
    userInfo = getOrganizations()[1]["assigned_users"]

    return userInfo


stakeholder_full_blueprint = Blueprint(
    "stakeholder_full", __name__, template_folder="templates/stakeholder_full_UI"
)


def getNames(url):

    doc = nlp(getAbout(url))

    d = []

    for ent in doc.ents:
        d.append((ent.label_, ent.text))

    return d


def getAbout(url):
    thepage = requests.get(url).text

    soup = BeautifulSoup(thepage, "lxml")

    body = soup.body.text

    body = body.replace("\n", " ")
    body = body.replace("\t", " ")
    body = body.replace("\r", " ")
    body = body.replace("\xa0", " ")
    # body = re.sub(r'[^ws]', '', body)

    return body


def theExecs(URL):
    mytext = getAbout(URL)

    tokens = word_tokenize(mytext)

    thetag = pos_tag(tokens)

    ne_tree = nltk.ne_chunk(thetag)

    for x in ne_tree:
        if "PERSON" in x:
            print(x)

    regex_pattern = re.compile(r"[@_'’!#\-$%^&*()<>?/\|}{~:]")

    thereturn = getNames(URL)

    executives = []

    for hy in thereturn:

        # print(hy)

        if ("PERSON" in hy) and (hy[1] not in executives) and (len(hy[1]) < 50):
            # executives.append(hy[1])
            # print(hy[1])

            # if not regex_pattern.search(hy[1]) and len(hy[1].split()) > 1 and not difflib.get_close_matches(hy[1], executives):
            if not regex_pattern.search(hy[1]) and len(hy[1].split()) > 1:
                person = hy[1].split("  ")
                if len(person) <= 1:
                    # print(person)
                    executives.append(hy[1])
                    # print(f'{hy[0]} {hy[1]}')
    # print(executives)
    return executives


@stakeholder_full_blueprint.route("/stakeholder_full", methods=["GET", "POST"])
def stakeholder_full():
    """Process form information, instantiate form and render page template."""
    cust = False
    custDomainAliases = False
    custRootDomain = False
    custExecutives = False

    formExternal = InfoFormExternal()

    if formExternal.validate_on_submit():
        logging.info("Got to the submit validate")
        cust = formExternal.cust.data
        custDomainAliases = formExternal.custDomainAliases.data.split(",")
        custRootDomain = formExternal.custRootDomain.data.replace(" ", "").split(",")
        # custRootDomainValue = custRootDomain[0]
        custExecutives = formExternal.custExecutives.data
        formExternal.cust.data = ""
        formExternal.custDomainAliases = ""
        formExternal.custRootDomain.data = ""
        formExternal.custExecutives.data = ""

        allExecutives = list(theExecs(custExecutives))

        orgs = set_org_to_report_on(cust)

        if orgs.empty:
            logging.info("No org found for the given cyhy_id")
            flash(f"{cust} is not a valid cyhy_id", "warning")
            return redirect(url_for("stakeholder_full.stakeholder_full"))
        elif len(orgs) == 1:
            try:
                # Add roots and enumerate for subs
                for org_index, org in orgs.iterrows():
                    insert_roots(org, custRootDomain)
                    logging.info(
                        "root domains have been successfully added to the database"
                    )
                    roots = query_roots(org["organizations_uid"])
                    for root_index, root in roots.iterrows():
                        enumerate_and_save_subs(
                            root["root_domain_uid"], root["root_domain"]
                        )
                    logging.info(
                        "subdomains have been successfully added to the database"
                    )

                # Fill the cidrs
                fill_cidrs(orgs)
                logging.info("Filled all cidrs")

                # Fill IPs table by enumerating CIDRs (all orgs)
                # fill_ips_from_cidrs()

                # Connect to subs from IPs table (only new orgs)
                # connect_subs_from_ips(orgs)
                # logging.info("Filled and linked all IPs")

                # Connect to IPs from subs table (only new orgs)
                connect_ips_from_subs(orgs)

                allValidIP = get_cidrs_and_ips(orgs["organizations_uid"].iloc[0])

                setNewCSGOrg(
                    cust,
                    custDomainAliases,
                    custRootDomain,
                    allValidIP,
                    allExecutives,
                )

                # Run pe_dedupe
                logging.info("Running dedupe:")
                dedupe(orgs)
                logging.info("done")
            except ValueError as e:
                logging.error(f"An error occured: {e}")
                flash(f"An error occured: {e}", "warning")
            return redirect(url_for("stakeholder_full.stakeholder_full"))
        else:
            flash(
                "multiple orgs were found for the provided cyhy_id, this should not be possible",
                "danger",
            )

    return render_template(
        "home_stakeholder_full.html",
        formExternal=formExternal,
        cust=cust,
        custRootDomain=custRootDomain,
        custExecutives=custExecutives,
        custDomainAliases=custDomainAliases,
    )


@stakeholder_full_blueprint.route("/link_IPs", methods=["GET", "POST"])
def link_IPs():
    """Run link IPs script on all orgs that are set to report_on."""
    orgs = get_orgs_df()
    report_orgs = orgs[orgs["report_on"] == True]
    connect_subs_from_ips(report_orgs)
    logging.info("Filled and linked all IPs")
    return "nothing"


@stakeholder_full_blueprint.route("/fill_IPs", methods=["GET", "POST"])
def fill_IPs():
    """Run link IPs script on all orgs that are set to report_on."""
    logging.info("Filling IPS")
    fill_ips_from_cidrs()
    logging.info("Done Filling IPS")
    return "nothing"
