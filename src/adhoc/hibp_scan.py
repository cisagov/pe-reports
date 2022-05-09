"""HIBP scan."""
# Standard Python Libraries
import time

# Third-Party Libraries
from data.config import config, config2
from data.run import query_orgs
import pandas as pd
import psycopg2
from psycopg2 import OperationalError, show_psycopg2_exception
import psycopg2.extras as extras
import requests

# DB connection functions
CF_CONN_PARAMS = config2()
PE_CONN_PARAMS = config()
orgs_to_run = ["DOE"]


def connect(PARAMS):
    """Connect to the db."""
    "Connection to postgres database"
    conn = None
    try:
        conn = psycopg2.connect(**PARAMS)
    except OperationalError as err:
        show_psycopg2_exception(err)
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
    print("Success fetching the data source")
except Exception:
    print("Failed fetching the data source.")

# HIBP functions
Emails_URL = "https://haveibeenpwned.com/api/v2/enterprisesubscriber/domainsearch/"
Breaches_URL = "https://haveibeenpwned.com/api/v2/breaches"
params = {
    "Authorization": "Bearer p2jsEWGNXRfQYetV0vc8CGVKxKNvfcz4HM3FBN-HhoPg4fprYr-KOI6q1BaM-pHOxAcQ4b_vnrEZNSwg1DRfa3X8LZyjj-S-Tl84e1hFBMYriDLTmZmJrbWKJbzope7n4DZ9JOheYCclE7RSEd1Pgn66_7OkqAghUIZLmynMzq5S2oDc9r8YlgvZITYOQtcBCbXQGoUydVxqVbRCI40-p_d9c6-X_0shCd1Z4RiIKluqldYCI9VOsBP9XME5aYkc_QLuJT_L5Ne5_-Rrhs1ShosYnQ9Wjg7xHuKaCjzdoO5MRKk109GveNElGJyQzDxRbISVQvya3lIrqFD2kH4ixXlmRhg02hrpUT5Bsb-HGNp65AJrbFMkd-9XZUIvdY1nOlZw9qHx4lQ_wxOkPZBKwa1bZZW08zj-ejvkZEZGN7w"
}


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
    print(combined_data)
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
            print(status)
            print(r.text)
            print(f"Trying to run on {domain} again")
            if status == 502:
                time.sleep(60 * 3)


def execute_hibp_emails_values(conn, jsonList, table):
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
    ON CONFLICT (email, breach_name, name)
    DO NOTHING;"""
    values = [[value for value in dict.values()] for dict in jsonList]
    cursor = conn.cursor()
    # try:
    extras.execute_values(cursor, sql, values)
    conn.commit()
    print("Data inserted into credential_exposures successfully..")
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
        print("Data inserted into credential_breaches successfully..")
    except (Exception, psycopg2.DatabaseError) as err:
        print(err)
        cursor.close()


def main():
    """Run main."""
    CF_conn = connect("", CF_CONN_PARAMS)
    PE_conn = connect("", PE_CONN_PARAMS)
    try:
        source_uid = getDataSource(PE_conn, "HaveIBeenPwnd")[0]
        print("Success fetching the data source")
    except Exception:
        print("Failed fetching the data source.")

    """Get Crossfeed orgs"""
    cf_orgs_df = query_CF_orgs(CF_conn)
    cf_orgs_dict = cf_orgs_df.set_index("name").agg(list, axis=1).to_dict()

    PE_orgs = query_orgs("")
    breaches = get_breaches()
    compiled_breaches = breaches[1]
    b_list = []
    for breach in compiled_breaches.values():
        # print(breach)
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
    for i, row in PE_orgs.iterrows():
        pe_org_uid = row["organizations_uid"]
        org_name = row["name"]
        cyhy_id = row["cyhy_db_name"]

        if cyhy_id not in orgs_to_run and orgs_to_run:
            continue
        print(f"Running on {org_name}")
        subs = query_CF_subs(CF_conn, cf_orgs_dict[org_name][0]).sort_values(
            by="name", key=lambda col: col.str.count(".")
        )

        print(subs)

        for i, sub in subs.iterrows():
            print(f"Finding breaches for {sub['name']}")
            hibp_resp = get_emails(sub["name"])
            if hibp_resp:
                # print(emails)
                # flat = flatten_data(emails, sub['name'], compiled_breaches)
                creds_list = []
                for email, breach_list in hibp_resp.items():
                    # print(emails)
                    # for email, breach_list in emails.items():
                    subdomain = sub["name"]
                    root_domain = sub["fromRootDomain"]
                    for b in breach_list:
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
                print("there are ", len(creds_list), " creds found")
                # Insert new creds into the PE DB
                execute_hibp_emails_values(
                    PE_conn, creds_list, "public.credential_exposures"
                )


if __name__ == "__main__":
    main()
