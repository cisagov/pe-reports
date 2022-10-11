"""Script to enumerate subs based on a provided root domain."""
# Standard Python Libraries
import datetime
import json

# Third-Party Libraries
import pandas as pd
import requests

# cisagov Libraries
from pe_reports.data.db_query import connect, execute_values, get_orgs

# TODO: Add API key
API_WHOIS = ""


def query_roots(org_uid):
    """Query all ips that link to a cidr related to a specific org."""
    print(org_uid)
    conn = connect()
    sql = """SELECT r.root_domain_uid, r.root_domain FROM root_domains r
            where r.organizations_uid = %(org_uid)s
            and r.enumerate_subs = True
            """
    df = pd.read_sql(sql, conn, params={"org_uid": org_uid})
    conn.close()
    return df


def execute_subs(conn, dataframe):
    """Save subdomains dataframe to the P&E DB."""
    df = dataframe.drop_duplicates()
    except_clause = """ ON CONFLICT (sub_domain, root_domain_uid)
                    DO
                    NOTHING;"""
    execute_values(conn, df, "public.sub_domains", except_clause)


def get_data_source_uid(source):
    """Get data source uid."""
    conn = connect()
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


def getSubdomain(domain, root_uid):
    """Get all sub-domains from passed in root domain."""
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
    print(subdomains)

    data_source = get_data_source_uid("WhoisXML")
    found_subs = [
        {
            "sub_domain": domain,
            "root_domain_uid": root_uid,
            "data_source_uid": data_source,
        }
    ]
    for sub in subdomains:
        if sub != f"www.{domain}":
            found_subs.append(
                {
                    "sub_domain": sub,
                    "root_domain_uid": root_uid,
                    "data_source_uid": data_source,
                }
            )
    return found_subs


def enumerate_and_save_subs(root_uid, root_domain):
    """Enumerate subdomains basedon on a private root."""
    subs = getSubdomain(root_domain, root_uid)
    subs = pd.DataFrame(subs)
    conn = connect()
    execute_subs(conn, subs)


def main():
    """Query orgs and run them through the enuemeration function."""
    orgs = get_orgs("")
    for org_index, org in orgs.iterrows():
        roots = query_roots(org["organizations_uid"])
        for root_index, root in roots.iterrows():
            enumerate_and_save_subs(root["root_domain_uid"], root["root_domain"])


if __name__ == "__main__":
    main()
