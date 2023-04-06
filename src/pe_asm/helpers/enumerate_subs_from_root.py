"""Script to enumerate subs based on a provided root domain."""
# Standard Python Libraries
import datetime
import json
import logging

# Third-Party Libraries
import pandas as pd
import requests

# cisagov Libraries
from pe_reports.data.config import whois_xml_api_key
from pe_reports.data.db_query import (
    get_data_source_uid,
)
from pe_asm.data.cyhy_db_query import (
    pe_db_connect,
    pe_db_staging_connect,
    query_roots,
    insert_sub_domains,
    identify_sub_changes,
)

LOGGER = logging.getLogger(__name__)
API_WHOIS = whois_xml_api_key()
DATE = datetime.datetime.today().date()


def enumerate_roots(root_domain, root_uid):
    """Get all sub-domains from passed in root domain."""
    url = "https://domains-subdomains-discovery.whoisxmlapi.com/api/v1"
    payload = json.dumps(
        {
            "apiKey": f"{API_WHOIS}",
            "domains": {"include": [f"{root_domain}"]},
            "subdomains": {"include": ["*"], "exclude": []},
        }
    )
    headers = {"Content-Type": "application/json"}
    response = requests.request("POST", url, headers=headers, data=payload)
    data = response.json()
    sub_domains = data["domainsList"]
    print(len(sub_domains))

    data_source = get_data_source_uid("WhoisXML")

    # First add the root domain to the subs table
    found_subs = [
        {
            "sub_domain": root_domain,
            "root_domain_uid": root_uid,
            "data_source_uid": data_source,
            "first_seen": DATE,
            "last_seen": DATE,
            "identified": False,
        }
    ]

    # Loop through the subdomain list and attach foreign keys
    for sub in sub_domains:
        if sub != f"www.{root_domain}":
            found_subs.append(
                {
                    "sub_domain": sub,
                    "root_domain_uid": root_uid,
                    "data_source_uid": data_source,
                    "first_seen": DATE,
                    "last_seen": DATE,
                    "identified": False,
                }
            )
    return found_subs


def get_subdomains(staging):
    """Enumerate roots and save subdomains."""
    # Connect to database
    if staging:
        conn = pe_db_staging_connect()
    else:
        conn = pe_db_connect()

    # Query root domains
    roots_df = query_roots(conn)
    total_roots = len(roots_df.index)
    LOGGER.info("Got %d root domains.", total_roots)

    # Loop through roots
    count = 0
    for root_index, root_row in roots_df.iterrows():

        # Enumerate for sub-domains
        print(root_row["root_domain"])
        subs = enumerate_roots(root_row["root_domain"], root_row["root_domain_uid"])

        # Create DataFrame
        subs_df = pd.DataFrame(subs)

        # Insert into P&E database
        insert_sub_domains(conn, subs_df)

        count += 1
        if count % 10 == 0 or count == total_roots:
            LOGGER.info("\t\t%d/%d complete.", count, total_roots)

    # Identify which Sub-domians are current
    LOGGER.info("Identify changes.")
    identify_sub_changes(conn)
    LOGGER.info("Success.")

    # Close database connection
    conn.close()


def main():
    """Query orgs and run them through the enuemeration function."""
    get_subdomains(False)


if __name__ == "__main__":
    main()
