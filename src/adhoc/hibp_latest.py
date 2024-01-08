"""HIBP scan."""
# Standard Python Libraries
import logging
import time
import threading

# Third-Party Libraries
from data.config import config, config2, get_hibp_token
from data.run import query_orgs
import numpy as np
import pandas as pd
import psycopg2
import psycopg2.extras as extras
import requests

# DB connection functions
CF_CONN_PARAMS = config2()
PE_CONN_PARAMS = config()
orgs_to_run = []

CENTRAL_LOGGING_FILE = "pe_reports_logging.log"
DEBUG = False
# Setup Logging
"""Set up logging and call the run_pe_script function."""
if DEBUG is True:
    level = "DEBUG"
else:
    level = "INFO"

logging.basicConfig(
    filename=CENTRAL_LOGGING_FILE,
    filemode="a",
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    datefmt="%m/%d/%Y %I:%M:%S",
    level=level,
)
LOGGER = logging.getLogger(__name__)


def connect(PARAMS):
    """Connect to the db."""
    "Connection to postgres database"
    conn = None
    try:
        conn = psycopg2.connect(**PARAMS)
    except Exception as err:
        LOGGER.info(err)
        LOGGER.info("Error connecting to DB.")
        conn = None
    return conn


def query_CF_orgs(conn):
    """Query Crossfeed orgs."""
    sql = """select o.name, o.id
            from organization o
            join organization_tag_organizations_organization otoo on otoo."organizationId" = o."id"
            join organization_tag ot on ot.id = otoo."organizationTagId"
            WHERE ot.name = 'P&E'"""
    df = pd.read_sql_query(sql, conn)
    return df


def query_CF_subs(conn, CF_org_id):
    """Query crossfeed subdomains."""
    sql = """
        SELECT d.name, d.ip, d."fromRootDomain"
        FROM domain d
        where d."organizationId" = %(org_id)s;
    """
    df = pd.read_sql_query(sql, conn, params={"org_id": CF_org_id})
    return df


def query_PE_subs(conn, PE_org_id):
    """Query Posture and Exposure subdomains."""
    sql = """
        SELECT sd.sub_domain, rd.root_domain
        FROM sub_domains sd
        join root_domains rd on rd.root_domain_uid = sd.root_domain_uid
        where rd.organizations_uid = %(org_id)s;"""
    df = pd.read_sql_query(sql, conn, params={"org_id": PE_org_id})
    return df


def getDataSource(conn, source):
    """Get the data source."""
    cur = conn.cursor()
    sql = """SELECT * FROM data_source WHERE name='{}'"""
    cur.execute(sql.format(source))
    source = cur.fetchone()
    cur.close()
    return source


try:
    PE_conn = connect(PE_CONN_PARAMS)
    source_uid = getDataSource(PE_conn, "HaveIBeenPwnd")[0]
    LOGGER.info("Success fetching the data source")
except Exception:
    LOGGER.error("Failed fetching the data source.")

# HIBP functions
Emails_URL = "https://haveibeenpwned.com/api/v2/enterprisesubscriber/domainsearch/"
Breaches_URL = "https://haveibeenpwned.com/api/v2/breaches"
# TODO: Add bearer token
token = get_hibp_token()
params = {"Authorization": f"Bearer {token}"}


def flatten_data(response, subdomain, breaches_dict):
    """Flatten data."""
    combined_data = []
    # loop through the json response
    if response:
        for key, value in response.items():
            # for each email loop through the list of breaches
            for b in value:
                data = {"email": key + "@" + subdomain, "sub_domain": subdomain}
                data.update(breaches_dict[b])
                combined_data.append(data)
    # LOGGER.info(combined_data)
    return combined_data


def get_breaches():
    """Get breaches."""
    breaches = requests.get(Breaches_URL, headers=params)
    breach_list = []
    breach_dict = {}
    if breaches.status_code == 200:
        jsonResponse = breaches.json()
        for line in jsonResponse:
            breach = {
                "breach_name": line["Name"],
                "breach_date": line["BreachDate"],
                "added_date": line["AddedDate"],
                "exposed_cred_count": line["PwnCount"],
                "modified_date": line["ModifiedDate"],
                "data_classes": line["DataClasses"],
                "description": line["Description"],
                "is_verified": line["IsVerified"],
                "is_fabricated": line["IsFabricated"],
                "is_sensitive": line["IsSensitive"],
                "is_retired": line["IsRetired"],
                "is_spam_list": line["IsSpamList"],
            }
            if "Passwords" in line["DataClasses"]:
                breach["password_included"] = True
            else:
                breach["password_included"] = False
            breach_list.append(breach)
            breach_dict[line["Name"]] = breach
        return (pd.DataFrame(breach_list), breach_dict)
    else:
        print(breaches.text)


def get_emails(domain):
    """Get emails."""
    run_failed = True
    counter = 0
    while run_failed:
        URL = Emails_URL + domain
        r = requests.get(URL, headers=params)
        status = r.status_code
        counter += 1
        if status == 200:
            return r.json()
        elif counter > 5:
            run_failed = False
        else:
            run_failed = True
            # LOGGER.info(status)
            # LOGGER.info(r.text)
            # LOGGER.info(f"Trying to run on {domain} again")
            if status == 502:
                time.sleep(60 * 3)


def execute_hibp_emails_values(conn, jsonList, thread):
    """Execute values."""
    "SQL 'INSERT' of a datafame"
    sql = """INSERT INTO public.credential_exposures (
        email,
        organizations_uid,
        root_domain,
        sub_domain,
        modified_date,
        breach_name,
        credential_breaches_uid,
        data_source_uid,
        name
    ) VALUES %s
    ON CONFLICT (email, breach_name)
    DO NOTHING;"""
    values = [[value for value in dict.values()] for dict in jsonList]
    cursor = conn.cursor()
    # try:
    extras.execute_values(cursor, sql, values)
    conn.commit()
    LOGGER.info("%s:\t\tHIBP data inserted into credential_exposures successfully..", thread)
    # except (Exception, psycopg2.DatabaseError) as err:
    #     show_psycopg2_exception(err)
    #     cursor.close()


def query_db(conn, query, args=(), one=False):
    """Query the database."""
    cur = conn.cursor()
    cur.execute(query, args)
    r = [
        {cur.description[i][0]: value for i, value in enumerate(row)}
        for row in cur.fetchall()
    ]

    return (r[0] if r else None) if one else r


def execute_hibp_breach_values(conn, jsonList, table):
    """Execute breach values."""
    "SQL 'INSERT' of a datafame"
    sql = """INSERT INTO public.credential_breaches (
        breach_name,
        description,
        exposed_cred_count,
        breach_date,
        added_date,
        modified_date,
        data_classes,
        password_included,
        is_verified,
        is_fabricated,
        is_sensitive,
        is_retired,
        is_spam_list,
        data_source_uid
    ) VALUES %s
    ON CONFLICT (breach_name)
    DO UPDATE SET modified_date = EXCLUDED.modified_date,
    exposed_cred_count = EXCLUDED.exposed_cred_count,
    password_included = EXCLUDED.password_included;"""
    values = [[value for value in dict.values()] for dict in jsonList]
    cursor = conn.cursor()
    try:
        extras.execute_values(cursor, sql, values)
        conn.commit()
        LOGGER.info("Data inserted into credential_breaches successfully..")
    except (Exception, psycopg2.DatabaseError) as err:
        LOGGER.error(err)
        cursor.close()

def hibp_thread(org_df, thread, compiled_breaches, breach_UIDS_Dict):
    for org_index, org_row in org_df.iterrows():
        pe_org_uid = org_row["organizations_uid"]
        org_name = org_row["name"]
        cyhy_id = org_row["cyhy_db_name"]
        # LOGGER.info(cyhy_id)

        if cyhy_id not in orgs_to_run and orgs_to_run:
            continue
        LOGGER.info(f"{thread}: Running HIBP on {cyhy_id}")

        subs = query_PE_subs(PE_conn, pe_org_uid).sort_values(
            by="sub_domain", key=lambda col: col.str.count(".")
        )

        # LOGGER.info(subs)

        for sub_index, sub in subs.iterrows():
            sd = sub["sub_domain"]
            if sd.endswith(".gov"):
                print(f"Finding breaches for {sd}")
            else:
                continue
            try:
                hibp_resp = get_emails(sd)
            except:
                LOGGER.info(f"{thread}: Failed after 5 tries.")
                continue
            if hibp_resp:
                # LOGGER.info(emails)
                # flat = flatten_data(emails, sub['name'], compiled_breaches)
                creds_list = []
                for email, breach_list in hibp_resp.items():
                    # LOGGER.info(emails)
                    # for email, breach_list in emails.items():
                    subdomain = sd
                    root_domain = sub["root_domain"]
                    for b in breach_list:
                        try:
                            cred = {
                                "email": email + "@" + subdomain,
                                "organizations_uid": pe_org_uid,
                                "root_domain": root_domain,
                                "sub_domain": subdomain,
                                "modified_date": compiled_breaches[b]["modified_date"],
                                "breach_name": b,
                                "credential_breaches_uid": breach_UIDS_Dict[b],
                                "data_source_uid": source_uid,
                                "name": None,
                            }
                            creds_list.append(cred)
                        except:
                            LOGGER.info("error adding cred to cred_list")
                LOGGER.info("%s:\t\tthere are %s creds found", thread, len(creds_list))
                # Insert new creds into the PE DB
                execute_hibp_emails_values(PE_conn, creds_list, thread)

def run_hibp(org_df):
    PE_conn = connect(PE_CONN_PARAMS)
    try:
        source_uid = getDataSource(PE_conn, "HaveIBeenPwnd")[0]
        LOGGER.info("Success fetching the data source")
    except Exception:
        LOGGER.error("Failed fetching the data source.")

    breaches = get_breaches()
    compiled_breaches = breaches[1]
    b_list = []
    for breach in compiled_breaches.values():
        # LOGGER.info(breach)
        breach_dict = {
            "breach_name": breach["breach_name"],
            "description": breach["description"],
            "exposed_cred_count": breach["exposed_cred_count"],
            "breach_date": breach["breach_date"],
            "added_date": breach["added_date"],
            "modified_date": breach["modified_date"],
            "data_classes": breach["data_classes"],
            "password_included": breach["password_included"],
            "is_verified": breach["is_verified"],
            "is_fabricated": breach["is_fabricated"],
            "is_sensitive": breach["is_sensitive"],
            "is_retired": breach["is_retired"],
            "is_spam_list": breach["is_spam_list"],
            "data_source_uid": source_uid,
        }
        b_list.append(breach_dict)

    execute_hibp_breach_values(PE_conn, b_list, "public.credential_breaches")
    sql = """SELECT breach."breach_name", breach."credential_breaches_uid" from public.credential_breaches as breach"""
    breaches_UIDs = query_db(PE_conn, sql)
    # Create a dictionary of each breach: UID combo
    breach_UIDS_Dict = {}
    for UID in breaches_UIDs:
        breach_UIDS_Dict.update({UID["breach_name"]: UID["credential_breaches_uid"]})


    orgs_list = np.array_split(org_df, 5)
    thread_list = []
    x = 0
    for org in orgs_list:
        thread_name = f"Thread {x+1}: "
        # Start thread
        t = threading.Thread(
            target=hibp_thread, args=(org, thread_name, compiled_breaches, breach_UIDS_Dict)
        )
        t.start()
        thread_list.append(t)
        x += 1

    for thread in thread_list:
        thread.join()
        


def main():
    """Run main."""
    PE_orgs = query_orgs("")

    run_hibp(PE_orgs)


if __name__ == "__main__":
    main()
