"""Flask application will add new stakeholder information to the PE Database.

Automate the process to add stakeholder information to Cyber Sixgill portal.
"""

# Standard Python Libraries
from datetime import date
from ipaddress import ip_address, ip_network
import json
import logging
import os
import socket

# Third-Party Libraries
# Local file import
# from data.config import config1, config2
from flask import Flask, flash, redirect,request, render_template, url_for
from flask_wtf import FlaskForm
import psutil
import psycopg2
import psycopg2.extras
from pymongo import MongoClient
from pymongo.errors import OperationFailure, ServerSelectionTimeoutError
import requests
from wtforms import SelectField, StringField, SubmitField
from wtforms.validators import DataRequired
import sublist3r
from pe_reports import app



# app = Flask(__name__)
# app.config["SECRET_KEY"] = "bozotheclown"
# app.config["SWLALCHEMY_DATABASE_URI"] = "postgresql://postgres:"
#
# # CSG credentials
# API_Client_ID = os.getenv("CSGUSER")
# API_Client_secret = os.environ.get("CSGSECRET")
# conn = None
# cursor = None
# thedateToday = date.today().strftime("%Y-%m-%d")
#
#
# def getToken():
#     """Will get authorization token from CSG."""
#     d = {
#         "grant_type": "client_credentials",
#         "client_id": f"{API_Client_ID}",
#         "client_secret": f"{API_Client_secret}",
#     }
#     r = requests.post("https://api.cybersixgill.com/auth/token", data=d)
#     r = r.text.split(":")
#     r = r[1].lstrip('"').rsplit('"')[0]
#     return r
#
#
# def cyhybastionConn():
#     """Check for cyhyDB connection and if not connected, make the connection."""
#     myprocess = os.popen("w")
#
#     pro1 = myprocess.read()
#
#     if "bastion" in pro1:
#         logging.info("This application has a connection to the cyhy db...")
#         return True
#     else:
#
#         logging.info("There was a problem connecting to the cyhy bastion.")
#         return False
#
#
# def terminatecyhyssh():
#     """Terminate the cyhyDB connection."""
#     for theprocess in psutil.process_iter():
#         if theprocess.name() == "ssh":
#             logging.info("The process was found")
#             theprocess.terminate()
#             logging.info("The process was terminated")
#         else:
#             pass
#
#
# def cyhyGet():
#     """Make connection to cyhyDB and query/return agency information."""
#     myinfo = config2()
#     host = myinfo["host"]
#     user = myinfo["user"]
#     password = myinfo["password"]
#     port = myinfo["port"]
#     dbname = myinfo["database"]
#     agencyInfo = {}
#     agencyNames = []
#
#     try:
#
#         CONNECTION_STRING = f"mongodb://{user}:{password}@{host}:{port}/{dbname}"
#
#         client = MongoClient(CONNECTION_STRING, serverSelectionTimeoutMS=2000)
#
#         mydb = client["cyhy"]
#
#         myfirstcoll = mydb["requests"]
#
#         # allcollections = mydb.list_collection_names()
#
#         getAllData = myfirstcoll.find()
#
#         for x in getAllData:
#             allAgency = x["_id"]
#             agencyNames.append(allAgency)
#             # allIPS is a list of all ip and subnets
#             allIPS = x["networks"]
#
#             agencyInfo[allAgency] = allIPS
#
#             # theAgency = x['acronym']
#     except OperationFailure as e:
#         logging.error(f"There was a problem connecting to the database {e}")
#     except ServerSelectionTimeoutError as err:
#         logging.error(f"The cyhy db connection was not avalible.{err}")
#
#     return agencyInfo, agencyNames


# class InfoFormExternal(FlaskForm):
#     """Create web form to take user input on organization information/details."""
#
#     cust = StringField("What is the stakeholder name?", validators=[DataRequired()])
#     # custIP = StringField(
#     #     "What is the stakeholder ip/cidr? *comma separate entries",
#     #     validators=[DataRequired()],
#     # )
#     custRootDomain = StringField(
#         "What is the root domain for this stakeholder? " "*comma separate entries"
#     )
#     custDomainAliases = StringField(
#         "What are the organization aliases? " "*comma separate entries"
#     )
#     # custSubDomain = StringField(
#     #     "What is the sub-domain for this stakeholder?" " *comma separate entries"
#     # )
#     custExecutives = StringField(
#         "Who are the Excutive for this stakeholder? " "*comma separate entries"
#     )
#     submit = SubmitField("Submit", render_kw={'onclick': 'loading()'})
#
#
# class InfoForm(FlaskForm):
#     """Create web form to choose an agency from the cyhyDB."""
#
#     # cyhybastionConn()
#     cust = SelectField("Choose Agency", choices=cyhyGet()[1])
#     submit = SubmitField("Submit")


# def getAgencies(org_name):
#     """Get all agency names from P&E database."""
#     global conn, cursor
#     resultDict = {}
#     try:
#         params = config1()
#
#         conn = psycopg2.connect(**params)
#
#         if conn:
#             logging.info(
#                 "There was a connection made to"
#                 "the database and the query was executed. "
#             )
#
#             cursor = conn.cursor(cursor_factory=psycopg2.extras.DictCursor)
#
#             cursor.execute(
#                 f"select organizations_uid,name from"
#                 f" organizations where name='{org_name}';"
#             )
#
#             result = cursor.fetchall()
#
#             for row in result:
#                 theOrgUUID = row[0]
#                 theOrgName = row[1]
#
#                 resultDict[f"{theOrgUUID}"] = f"{theOrgName}"
#             return resultDict
#
#     except (Exception, psycopg2.DatabaseError) as err:
#         logging.error(f"There was a problem logging into the psycopg database {err}")
#     finally:
#         if conn is not None:
#             cursor.close()
#             conn.close()
#             logging.info("The connection/query was completed and closed.")
#
#             return resultDict
#
#
# def getRootID(org_UUID):
#     """Get all agency names from P&E database."""
#     global conn, cursor
#     resultDict = {}
#     try:
#         params = config1()
#
#         conn = psycopg2.connect(**params)
#
#         if conn:
#             logging.info(
#                 "There was a connection made to the database and the query was executed "
#             )
#
#             cursor = conn.cursor(cursor_factory=psycopg2.extras.DictCursor)
#
#             cursor.execute(
#                 f"select root_domain_uid, organization_name from"
#                 f" root_domains where organizations_uid='{org_UUID}';"
#             )
#
#             result = cursor.fetchall()
#
#             for row in result:
#                 theRootUUID = row[0]
#                 theOrgName = row[1]
#
#                 resultDict[f"{theOrgName}"] = f"{theRootUUID}"
#             return resultDict
#
#     except (Exception, psycopg2.DatabaseError) as err:
#         logging.error(f"There was a problem logging into the psycopg database {err}")
#     finally:
#         if conn is not None:
#             cursor.close()
#             conn.close()
#             logging.info("The connection/query was completed and closed.")
#
#             return resultDict
#
#
# def setStakeholder(customer):
#     """Insert customer into the PE-Reports database."""
#     global conn, cursor
#
#     try:
#         logging.info("Starting insert into database...")
#
#         params = config1()
#
#         conn = psycopg2.connect(**params)
#
#         if conn:
#
#             logging.info(
#                 "There was a connection made to "
#                 "the database and the query was executed "
#             )
#
#             cursor = conn.cursor()
#
#             cursor.execute(f"insert into organizations(name)" f"values('{customer}')")
#
#             return True
#
#     except (Exception, psycopg2.DatabaseError) as err:
#         logging.error(f"There was a problem logging into the psycopg database {err}")
#         return False
#     finally:
#         if conn is not None:
#             conn.commit()
#             cursor.close()
#             conn.close()
#             logging.info("The connection/query was completed and closed.")
#             terminatecyhyssh()
#
#
# def setCustRootDomain(customer, rootdomain, orgUUID):
#     """Insert customer into the PE-Reports database."""
#     global conn, cursor
#
#     # customerInfo = rootdomain
#     try:
#         logging.info("Starting insert into database...")
#
#         params = config1()
#
#         conn = psycopg2.connect(**params)
#
#         if conn:
#
#             logging.info(
#                 "There was a connection made to "
#                 "the database and the query was executed "
#             )
#
#             cursor = conn.cursor()
#
#             cursor.execute(
#                 f"insert into root_domains("
#                 f"organizations_uid,"
#                 f"organization_name,"
#                 f" root_domain)"
#                 f"values('{orgUUID}', '{customer}','{rootdomain}');"
#             )
#             return True
#
#     except (Exception, psycopg2.DatabaseError) as err:
#         logging.error(f"There was a problem logging into the psycopg database {err}")
#         return False
#     finally:
#         if conn is not None:
#             conn.commit()
#             cursor.close()
#             conn.close()
#             logging.info("The connection/query was completed and closed.")
#             terminatecyhyssh()
#
#
# def setCustSubDomain(subdomain, rootUUID, rootname):
#     """Insert customer into the PE-Reports database."""
#     global conn, cursor
#
#     # customerInfo = rootdomain
#     try:
#
#         logging.info("Starting insert into database...")
#
#         params = config1()
#
#         conn = psycopg2.connect(**params)
#
#         if conn:
#
#             logging.info(
#                 "There was a connection made to "
#                 "the database and the query to "
#                 "insert the subdomains was executed "
#             )
#
#             cursor = conn.cursor()
#
#             for sub in subdomain:
#                 cursor.execute(
#                     f"insert into sub_domains("
#                     f"sub_domain,"
#                     f"root_domain_uid,"
#                     f" root_domain)"
#                     f"values('{sub}',"
#                     f" '{rootUUID}',"
#                     f"'{rootname}');"
#                 )
#             return True
#
#     except (Exception, psycopg2.DatabaseError) as err:
#         logging.error(f"There was a problem logging into the psycopg database {err}")
#         return False
#     finally:
#         if conn is not None:
#             conn.commit()
#             cursor.close()
#             conn.close()
#             logging.info("The connection/query was completed and closed.")
#             terminatecyhyssh()
#
#
# def setCustomerExteralCSG(
#     customer, customerIP, customerRootDomain, customerSubDomain, customerExecutives
# ):
#     """Insert customer not in cyhyDB into the PE-Reports database."""
#     global conn, cursor
#
#     iplist = []
#     domainlist = []
#     try:
#         logging.info("Starting insert into database...")
#
#         params = config1()
#
#         conn = psycopg2.connect(**params)
#
#         if conn:
#
#             logging.info(
#                 "There was a connection made to"
#                 " the database and the query was executed "
#             )
#
#             cursor = conn.cursor()
#
#             for ip in customerIP:
#                 iplist.append(ip)
#
#                 cursor.execute(
#                     f"insert into organizations(domain_name,"
#                     f" domain_ip,"
#                     f" date_saved) "
#                     f"values('{customer}',"
#                     f" '{ip}',"
#                     f"'{thedateToday}');"
#                 )
#             for domain in customerRootDomain:
#                 domainlist.append(domain)
#                 cursor.execute(
#                     f"insert into domain_assets(domain_name,"
#                     f" domain_ip,"
#                     f" date_saved) "
#                     f"values('{customer}',"
#                     f" '{ip}', '{thedateToday}');"
#                 )
#
#     except (Exception, psycopg2.DatabaseError) as err:
#         logging.error(f"There was a problem logging into the psycopg database {err}")
#     finally:
#         if conn is not None:
#             conn.commit()
#             cursor.close()
#             conn.close()
#             logging.info("The connection/query was completed and closed.")
#             terminatecyhyssh()
#     return iplist
#
# def getSubdomain(domain):
#     """Get all sub-domains from passed in root domain."""
#     allsubs = []
#
#     subdomains = sublist3r.main(domain, 40,None,None,False,False,False,None)
#     subisolated = ''
#     for sub in subdomains:
#
#         if sub != f'www.{domain}':
#
#             print(sub)
#             subisolated = sub.rsplit('.')[:-2]
#             # subisolated = sub.rsplit('.',2)[:-2]
#             print(f'The whole sub is {sub} and '
#                   f'the isolated sub is {subisolated}')
#         allsubs.append(subisolated)
#
#     return subdomains,allsubs
#
# def theaddress(domain):
#     """Get actual IP address of domain
#
#     """
#
#     gettheAddress = ''
#
#     try:
#         gettheAddress = socket.gethostbyname(domain)
#     except socket.gaierror:
#         pass
#         logging.info('There is a problem with the Domain that you selected')
#
#     return gettheAddress
#
# def getallsubdomainIPS(domain):
#     logging.info(f'The domain at getallsubdomsinIPS is {domain}')
#     alladdresses = []
#     for x in getSubdomain(domain)[0]:
#         domainaddress = theaddress(x)
#         if domainaddress not in alladdresses and domainaddress != '':
#             alladdresses.append(domainaddress)
#     return alladdresses
#
#
# def verifyIPv4(custIP):
#     """Verify if parameter is a valid ipv4 ip address."""
#     try:
#         if ip_address(custIP) :
#             return True
#
#         else:
#             return False
#
#     except ValueError as err:
#         logging.error(f"The address is incorrect, {err}")
#         return False
#
#
# def verifyCIDR(custIP):
#     """Verify if parameter is a valid CIDR block ip address."""
#     try:
#         if ip_network(custIP):
#             return True
#
#         else:
#             return False
#
#     except ValueError as err:
#         logging.error(f"The cidr is incorrect, {err}")
#         return False
#
#
# def validateIP(custIP):
#     """
#     Verify ipv4 and cidr.
#
#     Collect address information into a list that is ready for DB insertion.
#     """
#     verifiedIP = []
#     for the_ip in custIP:
#         if verifyCIDR(the_ip) or verifyIPv4(the_ip):
#             verifiedIP.append(the_ip)
#     return verifiedIP
#
#
# def getOrganizations():
#     """Get all orgaization details from Cybersix Gill via API."""
#     url = "https://api.cybersixgill.com/multi-tenant/organization"
#
#     headers = {
#         "Content-Type": "application/json",
#         "Cache-Control": "no-cache",
#         "Authorization": f"Bearer {getToken()}",
#     }
#
#     response = requests.get(url, headers=headers).json()
#     return response
#
#
# def setNewCSGOrg(newOrgName, orgAliases, orgdomainNames, orgIP, orgExecs):
#     """Set a new stakeholder name at CSG."""
#     newOrganization = json.dumps(
#         {
#             "name": f"{newOrgName}",
#             "organization_commercial_category": "customer",
#             "countries": ["worldwide"],
#             "industries": ["Government"],
#         }
#     )
#     url = "https://api.cybersixgill.com/multi-tenant/organization"
#
#     headers = {
#         "Content-Type": "application/json",
#         "Cache-Control": "no-cache",
#         "Authorization": f"Bearer {getToken()}",
#     }
#
#     response = requests.post(url, headers=headers, data=newOrganization).json()
#
#     newOrgID = response["id"]
#
#     if newOrgID:
#         logging.info(f"Got here there is a new new org {newOrgID}")
#
#         setOrganizationUsers(newOrgID)
#         setOrganizationDetails(newOrgID, orgAliases, orgdomainNames, orgIP, orgExecs)
#
#     return response
#
#
#
#
#
# #TODO update jira on this progress. Add an import for the logo in CSG and see if its possible to send the image with the API.
#
#
#
#
# def setOrganizationUsers(org_id ):
#     """Set CSG user permissions at new stakeholder."""
#     print(len(getalluserinfo()))
#     for user in getalluserinfo():
#         userrole = user['role_id']
#         user_id = user['user_id']
#         username = user['user_name']
#
#
#         if (userrole == '5d23342df5feaf006a8a8929') and (user_id != '610017c216948d7efa077a52') or userrole == '5d23342df5feaf006a8a8927' and user_id != '610017c216948d7efa077a52' :
#             print(f'The userrole {userrole} and the user_id {user_id} and the user {username}')
#             url = f"https://api.cybersixgill.com/multi-tenant/organization/{org_id}/user/{user_id}?role_id={userrole}"
#
#             headers = {
#                 'Content-Type': 'application/json',
#                 'Cache-Control': 'no-cache',
#                 'Authorization': f'Bearer {getToken()}',
#             }
#
#             response = requests.post(url, headers=headers).json()
#             logging.info(response)
#
#
# def setOrganizationDetails(org_id, orgAliases, orgDomain, orgIP, orgExecs):
#     """Set stakeholder details at newly created stakeholder at CSG portal via API.."""
#     print("The following is from setting details")
#     print(org_id)
#     print(orgAliases)
#     print(orgDomain)
#     print(orgIP)
#     print(orgExecs)
#     newOrganizationDetails = json.dumps(
#         {
#             "organization_aliases": {"explicit": orgAliases},
#             "domain_names": {"explicit": orgDomain},
#             "ip_addresses": {"explicit": orgIP},
#             "executives": {"explicit": orgExecs},
#         }
#     )
#     url = f"https://api.cybersixgill.com/multi-tenant/" f"organization/{org_id}/assets"
#
#     headers = {
#         "Content-Type": "application/json",
#         "Cache-Control": "no-cache",
#         "Authorization": f"Bearer {getToken()}",
#     }
#
#     response = requests.put(url, headers=headers, data=newOrganizationDetails).json()
#     logging.info(f"The response is {response}")
#
#
# def getalluserinfo():
#     """Get CSG user permission role information from GSG."""
#     userInfo = getOrganizations()[1]["assigned_users"]
#
#     return userInfo


@app.route("/", methods=["GET", "POST"])
def index():
    """Create add customer html form.
    Gather data from form and insert into database.
    """
    # cust = False
    # custDomainAliases = False
    # custRootDomain = False
    # custExecutives = False
    #
    # form = InfoForm()
    # formExternal = InfoFormExternal()
    #
    # # allCustIP = cyhyGet()[0]
    # cyhyconnected = cyhybastionConn()
    # # logging.info(f"The cyhy db is connected {cyhyconnected}")
    #
    # if form.validate_on_submit():
    #     cust = form.cust.data.upper()
    #     form.cust.data = ""
    #     allDomain = getAgencies(cust)
    #
    #     try:
    #
    #         if cust not in allDomain:
    #             flash(f"You successfully submitted a new customer {cust} ", "success")
    #             setStakeholder(cust)
    #         else:
    #             flash(
    #                 f"The customer that you selected already exists. {cust} ", "warning"
    #             )
    #
    #     except ValueError as e:
    #         flash(f"The customer IP {e} is not a valid IP, please try again.", "danger")
    #         return redirect(url_for("index"))
    #     return redirect(url_for("index"))
    #
    # if formExternal.validate_on_submit():
    #     logging.info('Got to the submit validate')
    #     cust = formExternal.cust.data.upper()
    #     # custIP = formExternal.custIP.data.split(",")
    #     custDomainAliases = formExternal.custDomainAliases.data.split(",")
    #     custRootDomain = formExternal.custRootDomain.data.split(",")
    #     custRootDomainValue = custRootDomain[0]
    #     # custSubDomain = formExternal.custSubDomain.data.split(",")
    #     custExecutives = formExternal.custExecutives.data.split(",")
    #
    #     formExternal.cust.data = ""
    #     # formExternal.custIP.data = ""
    #     formExternal.custDomainAliases = ""
    #     formExternal.custRootDomain.data = ""
    #     # formExternal.custSubDomain.data = ""
    #     formExternal.custExecutives.data = ""
    #     allDomain = getAgencies(cust)
    #     allSubDomain = getSubdomain(custRootDomainValue)
    #     allValidIP = getallsubdomainIPS(custRootDomainValue)
    #
    #     print(f'{cust}')
    #     print(f'{allDomain}')
    #     print(f'{allSubDomain}')
    #     print(f'{custDomainAliases}')
    #     print(f'{custRootDomainValue}')
    #     print(f'{allValidIP}')
    #     print(f'{custExecutives}')
    #
    #     try:
    #         print(allDomain.values())
    #         if cust not in allDomain.values():
    #             flash(f"You successfully submitted a new customer {cust} ",
    #                   "success")
    #
    #             if setStakeholder(cust):
    #                 logging.info(f"The customer {cust} was entered.")
    #                 allDomain = list(getAgencies(cust).keys())[0]
    #                 # print(allDomain)
    #
    #                 if setCustRootDomain(cust, custRootDomainValue, allDomain):
    #                     rootUUID = getRootID(allDomain)[cust]
    #
    #                     # print(rootUUID)
    #                     logging.info(
    #                         f"The Root Domain {custRootDomainValue} "
    #                         f"was entered at root_domains."
    #                     )
    #                     if allSubDomain:
    #                         for subdomain in allSubDomain:
    #                             if setCustSubDomain(subdomain, rootUUID, cust):
    #                                 logging.info("The subdomains have been entered.")
    #                                 setNewCSGOrg(
    #                                     cust,
    #                                     custDomainAliases,
    #                                     custRootDomain,
    #                                     allValidIP,
    #                                     custExecutives,
    #                                 )
    #
    #         else:
    #             flash(f"The customer already exists. {cust}", "warning")
    #
    #     except ValueError as e:
    #         flash(f"The customer IP {e} is not a valid IP, please try again.", "danger")
    #         return redirect(url_for("index"))
    #     return redirect(url_for("index"))

    return render_template('home.html')



if __name__ == "__main__":
    logging.info("The program has started...")
    app.run(debug=True, port=8000)
