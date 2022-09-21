"""Script to enumerate subs based on a provided root domain."""
# Standard Python Libraries
import datetime
import json

# Third-Party Libraries
import pandas as pd
import requests

# cisagov Libraries
from pe_reports.data.db_query import (
    connect,
    execute_values,
    get_orgs,
    query_roots,
    get_data_source_uid,
)
from pe_reports.data.config import whois_xml_api_key

# TODO: Add API key
API_WHOIS = whois_xml_api_key()


def execute_subs(conn, dataframe):
    """Save subdomains dataframe to the P&E DB."""
    df = dataframe.drop_duplicates()
    except_clause = """ ON CONFLICT (sub_domain, root_domain_uid)
                    DO
                    NOTHING;"""
    execute_values(conn, df, "public.sub_domains", except_clause)


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
    orgs = get_orgs(connect())
    for org_index, org_row in orgs.iterrows():
        roots = query_roots(org_row["organizations_uid"])
        for root_index, root_row in roots.iterrows():
            enumerate_and_save_subs(
                root_row["root_domain_uid"], root_row["root_domain"]
            )


if __name__ == "__main__":
    main()
