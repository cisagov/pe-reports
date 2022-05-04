"""DNSMonitor API calls and DNS lookups."""
# Standard Python Libraries
import socket

# Third-Party Libraries
import dns.resolver
import pandas as pd
import requests


def get_monitored_domains(token):
    """Get the domains being monitored."""
    org_names_df = pd.read_csv(
        "src/pe_source/data/dnsmonitor/root_domains_dnsmonitor.csv"
    )
    url = "https://dns.portal.truespd.com/dhs/api/GetDomains"
    payload = {}
    headers = {}
    headers["authorization"] = f"Bearer {token}"
    response = requests.request("GET", url, headers=headers, data=payload).json()
    df = pd.DataFrame(response)

    # Sync domainid's with org names
    df["org"] = "NA"
    for i, row in org_names_df.iterrows():
        for i2, row2 in df.iterrows():
            if row["domain_name"] == row2["domainName"]:
                df.at[i2, "org"] = row["org"]
    return df


def get_domain_alerts(token, domain_ids, from_date, to_date):
    """Get domain alerts."""
    url = "https://dns.portal.truespd.com/dhs/api/GetAlerts"
    payload = (
        '{\r\n  "domainIds": %s,\r\n  "fromDate": "%s",\r\n  "toDate": "%s",\r\n  "alertType": null,\r\n  "showBufferPeriod": false\r\n}'
        % (domain_ids, from_date, to_date)
    )
    headers = {}
    headers["authorization"] = f"Bearer {token}"
    headers["Content-Type"] = "application/json"
    response = requests.request("GET", url, headers=headers, data=payload).json()
    return pd.DataFrame(response)


def get_dns_records(dom_perm):
    """Get DNS records."""
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

    return str(mx_list), str(ns_list), ipv4, ipv6
