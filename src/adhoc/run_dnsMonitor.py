"""Run DNS Monitor scan."""
# Standard Python Libraries
import datetime
import socket

# Third-Party Libraries
# sys.path is a list of absolute path strings
# sys.path.append("/Users/loftusa/Documents/PE/Scripts/Testing/pe_db")
from data.run import (
    addRootToSubdomain,
    execute_dnsmonitor_alert_data,
    execute_dnsmonitor_data,
    getDataSource,
    getSubdomain,
    query_orgs,
)
import dns.resolver
import pandas as pd
import requests


def get_dates():
    """Get dates."""
    end = datetime.datetime.now()
    d = datetime.timedelta(days=20)
    d2 = datetime.timedelta(days=1)
    start = end - d
    end = end + d2
    return start, end


# Get root domain csv with organization labels
org_names_df = pd.read_csv("/home/ubuntu/adhoc/data/root_domains_dns_monitor.csv")

# Get Token
# client_id = ""
# client_secret = ""
scope = "DNSMonitorAPI"
url = "https://portal.truespd.com/dhs/connect/token"

# TODO: Insert client id and secret values
payload = {
    "client_id": "",
    "client_secret": "",
    "grant_type": "client_credentials",
    "scope": scope,
}

response = requests.request("POST", url, headers={}, data=payload, files=[]).json()
token = response["access_token"]

# Get all of the Domains being monitored
url = "https://dns.portal.truespd.com/dhs/api/GetDomains"
payload = {}
headers = {}
headers["authorization"] = f"Bearer {token}"
response = requests.request("GET", url, headers=headers, data=payload).json()
df = pd.DataFrame(response)
print(df)


# Sync domainid's with org names
df["org"] = "NA"
for i, row in org_names_df.iterrows():
    for i2, row2 in df.iterrows():
        if row["domain_name"] == row2["domainName"]:
            df.at[i2, "org"] = row["org"]

""" Get Orgs """
orgs = query_orgs("")

from_date, to_date = get_dates()

# Iterate through each org
for i, row in orgs.iterrows():
    # Get a list of the org's DomainIds that DNS Monitor assigned
    org = row["name"]
    # if (
    #     org != "National Aeronautics and Space Administration"
    #     and org != "Nuclear Regulatory Commission"
    #     and org != "Office of Personnel Management"
    # ):
    #     continue
    domainIds = df[df["org"] == org]
    domainIds = str(domainIds["domainId"].tolist())

    # Get Alerts for a specific org based on the list of DOomainIds
    if domainIds == "[]":
        print("Can't match org to any domains...")
    else:
        url = "https://dns.portal.truespd.com/dhs/api/GetAlerts"
        payload1 = (
            '{\r\n  "domainIds": %s,\r\n  "fromDate": "%s",\r\n  "toDate": "%s",\r\n  "alertType": null,\r\n  "showBufferPeriod": false\r\n}'
            % (domainIds, from_date, to_date)
        )
        print("\n\n" + org + ":")
        print(payload1)
        headers = {}
        headers["authorization"] = f"Bearer {token}"
        headers["Content-Type"] = "application/json"
        response = requests.request("GET", url, headers=headers, data=payload1).json()
        alerts_df = pd.DataFrame(response)
        # If no alerts, continue
        if alerts_df.empty:
            print(f"No alerts for {org}.")
            continue
        print(alerts_df)

        # Now that we have all the alerts, get the sub_domain_uid for each
        # df["sub_domain_uid"] = ""
        # df["mx_records"] = []
        # df["ns_records"] = []
        # df["ip_address"] = ""
        for i, r in alerts_df.iterrows():
            root_domain = r["rootDomain"]
            sub_domain = getSubdomain(root_domain)
            # DNSMonitor only monitor roots and table relationships are org --> root_domain --> subdomain --> domain_permutations --> domain_alerts
            # So the subdomain table needs to have roots in them as well as a "sub_domain"
            if not sub_domain:
                print(
                    f"Root domain, {root_domain}, isn't in sub domain table as a sub_domain."
                )
                addRootToSubdomain(root_domain)
                sub_domain = getSubdomain(root_domain)

            # Add subdomain_uid to associated alert
            sub_domain_uid = sub_domain[0]
            alerts_df.at[i, "sub_domain_uid"] = sub_domain_uid

            # Get DNS records for each domain permutation
            dom_perm = r["domainPermutation"]
            # NS
            try:
                ns_list = []
                dom_ns = dns.resolver.resolve(dom_perm, "NS")
                for data in dom_ns:
                    ns_list.append(str(data.target))
            except Exception:
                ns_list = []
            # MX
            try:
                mx_list = []
                dom_mx = dns.resolver.resolve(dom_perm, "MX")
                for data in dom_mx:
                    mx_list.append(str(data.exchange))
            except Exception:
                mx_list = []

            # A
            try:
                ip_address = str(socket.gethostbyname(dom_perm))
                if ":" in ip_address:
                    ipv6 = ip_address
                    ipv4 = ""
                else:
                    ipv4 = ip_address
                    ipv6 = ""
            except Exception:
                ipv4 = ""
                ipv6 = ""

            # Add records to df
            alerts_df.at[i, "mail_server"] = str(mx_list)
            alerts_df.at[i, "name_server"] = str(ns_list)
            alerts_df.at[i, "ipv4"] = ipv4
            alerts_df.at[i, "ipv6"] = ipv6

        # Set the data_source_uid
        source = getDataSource("DNSMonitor")
        source_uid = source[0]
        alerts_df["data_source_uid"] = source_uid

        # Add other columns
        # alerts_df["fuzzer"] = None
        # alerts_df["ssdeep_score"] = None

        print(alerts_df)

        # Create df to insert into domain permtations table
        alerts_df = alerts_df.rename(
            columns={
                "domainPermutation": "domain_permutation",
                "dateCreated": "date_observed",
                "alertType": "alert_type",
                "previousValue": "previous_value",
                "newValue": "new_value",
            }
        )
        alerts_df["organizations_uid"] = row["organizations_uid"]
        dom_perm_df = alerts_df[
            [
                "organizations_uid",
                "sub_domain_uid",
                "data_source_uid",
                "domain_permutation",
                "ipv4",
                "ipv6",
                "mail_server",
                "name_server",
                "date_observed",
            ]
        ]
        dom_perm_df = dom_perm_df.drop_duplicates(
            subset=["domain_permutation"], keep="last"
        )
        execute_dnsmonitor_data(dom_perm_df, "domain_permutations")

        alerts_df = alerts_df.rename(columns={"date_observed": "date"})
        # Create df to insert into domain alerts table
        domain_alerts = alerts_df[
            [
                "organizations_uid",
                "sub_domain_uid",
                "data_source_uid",
                "alert_type",
                "message",
                "previous_value",
                "new_value",
                "date",
            ]
        ]
        print(domain_alerts)
        execute_dnsmonitor_alert_data(domain_alerts, "domain_alerts")
