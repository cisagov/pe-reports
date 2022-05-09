"""Sync Crossfeed's hibp data."""
# Standard Python Libraries
import sys
import traceback

# Third-Party Libraries
from data.config import config
import pandas as pd
import psycopg2
from psycopg2 import OperationalError
import psycopg2.extras as extras

CF_PARAMS_DIC = config(section="crossfeedDB")
PE_PARAMS_DIC = config()


def show_psycopg2_exception(err):
    """Error handleing for postgres issues."""
    err_type, traceback = sys.exc_info()
    line_n = traceback.tb_lineno
    print("\npsycopg2 ERROR:", err, "on line number:", line_n)
    print("psycopg2 traceback:", traceback, "-- type:", err_type)
    print("\nextensions.Diagnostics:", err)
    print("pgerror:", err)
    print("pgcode:", err, "\n")


def connect(Params_Dic):
    """Connect to the db."""
    print(Params_Dic)
    "Connection to postgres database"
    conn = None
    try:
        conn = psycopg2.connect(**Params_Dic)
    except OperationalError as err:
        show_psycopg2_exception(err)
        conn = None
    return conn


def query_db(conn, query, args=(), one=False):
    """Query the db."""
    cur = conn.cursor()
    cur.execute(query, args)
    r = [
        {cur.description[i][0]: value for i, value in enumerate(row)}
        for row in cur.fetchall()
    ]

    return (r[0] if r else None) if one else r


def query_CF_orgs(conn):
    """Query the Crossfeed orgs."""
    sql = """select o.name, o.id
        from organization o
        join organization_tag_organizations_organization otoo on otoo."organizationId" = o."id"
        join organization_tag ot on ot.id = otoo."organizationTagId"
        WHERE  ot.name  = 'P&E'"""
    df = pd.read_sql_query(sql, conn)
    print(df)
    conn.close()

    return df


def execute_hibp_breach_values(conn, jsonList, table):
    """Execute breach values."""
    "SQL 'INSERT' of a datafame"
    columns = jsonList[0].keys()
    sql = """INSERT INTO {}({}) VALUES %s
    ON CONFLICT (breach_name)
    DO UPDATE SET modified_date = EXCLUDED.modified_date,
    exposed_cred_count = EXCLUDED.exposed_cred_count,
    password_included = EXCLUDED.password_included;"""
    values = [[value for value in dict.values()] for dict in jsonList]
    cursor = conn.cursor()
    try:
        extras.execute_values(
            cursor,
            sql.format(
                table,
                ",".join(columns),
            ),
            values,
        )
        conn.commit()
        print("Data inserted using execute_values() successfully..")
    except (Exception, psycopg2.DatabaseError) as err:
        print(err)
        cursor.close()


def execute_hibp_emails_values(conn, jsonList, table):
    """Execute email values."""
    "SQL 'INSERT' of a datafame"
    columns = jsonList[0].keys()
    sql = """INSERT INTO {}({}) VALUES %s
    ON CONFLICT (email, breach_name, name)
    DO NOTHING;"""
    values = [[value for value in dict.values()] for dict in jsonList]
    cursor = conn.cursor()
    # try:
    extras.execute_values(
        cursor,
        sql.format(
            table,
            ",".join(columns),
        ),
        values,
    )
    conn.commit()
    print("Data inserted using execute_values() successfully..")
    # except (Exception, psycopg2.DatabaseError) as err:
    #     show_psycopg2_exception(err)
    #     cursor.close()


def getDataSource(conn, source):
    """Get data source."""
    cur = conn.cursor()
    sql = """SELECT * FROM data_source WHERE name='{}'"""
    cur.execute(sql.format(source))
    source = cur.fetchone()
    cur.close()
    return source


try:
    try:
        CF_conn = connect(CF_PARAMS_DIC)
        orgs_df = query_CF_orgs(CF_conn)
    except Exception as e:
        print(e)
        print("Failed to query Crossfeed Orgs")
        quit()
    for i, CF_org in orgs_df.iterrows():
        org_name = CF_org["name"]
        org_id = CF_org["id"]
        # Connect to PE DB
        try:
            PE_conn = connect(PE_PARAMS_DIC)
            print("Connected to PE database.")
        except Exception:
            print("Failed To Connect to PE database")

        # Query PE Db to get the Organization UID
        try:
            print(f"Running on organization: {org_name}")
            cur = PE_conn.cursor()
            sql = """SELECT organizations_uid FROM organizations WHERE name='{}'"""
            cur.execute(sql.format(org_name))
            pe_org_uid = cur.fetchone()[0]
            cur.close()
            print(f"PE_org_uid: {pe_org_uid}")
        except Exception:
            print("Failed with Select Statement")
            print(traceback.format_exc())

        # Get the Hibp data source uid
        try:
            source_uid = getDataSource(PE_conn, "HaveIBeenPwnd")[0]
            print("Success fetching the data source")
        except Exception:
            print("Failed fetching the data source.")

        # Connect to Crossfeed DB
        try:
            CF_conn = connect(CF_PARAMS_DIC)
            print("Connected to crossfeed database.")
        except Exception:
            print("Failed To Connect to crossfeed database")

        try:
            # Get a list of all HIBP Vulns for this organization
            sql = """SELECT vuln."structuredData", dom."fromRootDomain", dom."name"
                    FROM domain as dom
                    JOIN vulnerability as vuln
                    ON vuln."domainId" = dom.id
                    WHERE dom."organizationId" ='{}'
                    AND vuln."source" = 'hibp'"""

            hibp_resp = query_db(
                CF_conn,
                sql.format(org_id),
            )

            compiled_breaches = {}

            # Remove duplicate breaches
            for row in hibp_resp:
                compiled_breaches.update(row["structuredData"]["breaches"])
            # Loop through the breaches and create a breach object to insert into PE database
            b_list = []
            for breach in compiled_breaches.values():
                breach_dict = {
                    "breach_name": breach["Name"],
                    "description": breach["Description"],
                    "exposed_cred_count": breach["PwnCount"],
                    "breach_date": breach["BreachDate"],
                    "added_date": breach["AddedDate"],
                    "modified_date": breach["ModifiedDate"],
                    "data_classes": breach["DataClasses"],
                    "password_included": breach["passwordIncluded"],
                    "is_verified": breach["IsVerified"],
                    "is_fabricated": breach["IsFabricated"],
                    "is_sensitive": breach["IsSensitive"],
                    "is_retired": breach["IsRetired"],
                    "is_spam_list": breach["IsSpamList"],
                    "data_source_uid": source_uid,
                }
                b_list.append(breach_dict)
            # Insert new breaches into the PE DB, update changed breaches
            execute_hibp_breach_values(PE_conn, b_list, "public.credential_breaches")
            # Query PE DB for breaches to get Breach_UID
            sql = """SELECT breach."breach_name", breach."credential_breaches_uid" from public.credential_breaches as breach"""
            breaches_UIDs = query_db(PE_conn, sql)
            # Create a dictionary of each breach: UID combo
            breach_UIDS_Dict = {}
            for UID in breaches_UIDs:
                breach_UIDS_Dict.update(
                    {UID["breach_name"]: UID["credential_breaches_uid"]}
                )

            # Loop through each credential exposure and create an hibp_exposed_cred object to insert into db
            creds_list = []
            for row in hibp_resp:
                breaches = row["structuredData"]["breaches"]
                emails = row["structuredData"]["emails"]
                for email, breach_list in emails.items():
                    subdomain = row["name"]
                    root_domain = row["fromRootDomain"]
                    for b in breach_list:
                        cred = {
                            "email": email,
                            "organizations_uid": pe_org_uid,
                            "root_domain": root_domain,
                            "sub_domain": subdomain,
                            "modified_date": compiled_breaches[b]["ModifiedDate"],
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
            # Close DB connection
            PE_conn.close()
            CF_conn.close()

        except Exception:
            print(traceback.format_exc())
            print("failed to query crossfeed db")


except Exception:
    print("Failed")
