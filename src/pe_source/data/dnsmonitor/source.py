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
        "/var/www/pe-reports/src/pe_source/data/dnsmonitor/root_domains_dnsmonitor.csv"
    )
    url = "https://dns.argosecure.com/dhs/api/GetDomains"
    payload = {}
    headers = {}
    headers["authorization"] = f"Bearer {token}"
    response = requests.request("GET", url, headers=headers, data=payload).json()
    domain_df = pd.DataFrame(response)

    # Sync domainid's with org names
    domain_df["org"] = "NA"
    for org_index, org_row in org_names_df.iterrows():
        for domain_index, domain_row in domain_df.iterrows():
            if org_row["domain_name"] == domain_row["domainName"]:
                domain_df.at[domain_index, "org"] = org_row["org"]
    return domain_df


def get_domain_alerts(token, domain_ids, from_date, to_date):
    """Get domain alerts."""
    url = "https://dns.argosecure.com/dhs/api/GetAlerts"
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
