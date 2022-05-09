"""Script to verify ips resolve to orgs root domains.

Usage:
  ip_validation [ORGS...]

Options:
  -h --help                         Show this message.
  ORGS                              Optional list of org_ids to run on (no commas or spaces in between).
"""
# Standard Python Libraries
import logging
import socket
import traceback

# Third-Party Libraries
from data.run import close, connect, query_ips, query_orgs_rev, query_roots
from docopt import docopt
import psycopg2
import requests


def update_ip(ip, org_uid, domain):
    """Update IP."""
    try:

        conn = connect("")

        if conn:

            logging.info("There was a connection made to the database")

            cursor = conn.cursor()

            cursor.execute(
                """
                UPDATE web_assets
                SET report_on = False, report_status_reason=%s
                WHERE  organizations_uid = %s
                AND asset = %s
                """,
                (
                    f"Resolved domain {str(domain)} does not match any root domains",
                    org_uid,
                    ip,
                ),
            )

    except (Exception, psycopg2.DatabaseError) as err:
        print("setsubinfo error")
        logging.error(f"There was a problem logging into the psycopg database {err}")
    finally:
        if conn:
            conn.commit()
            cursor.close()
            conn.close()
            logging.info("The connection/query was completed and closed.")


def ip_domain_compare(ip, domain_list, org_uid):
    """Compare IP."""
    ip_address = ip["ip_address"]
    org_uid = org_uid
    # sub_domain = thehostname(ip_address)
    subs, roots = reverseLookup(ip_address)

    if roots:
        if len(roots.intersection(domain_list)) == 0:
            update_ip(ip_address, org_uid, subs)
            print(f"{ip_address} resolved to {str(roots)}")


def thehostname(domainIP):
    """Get actual domain from an IP."""
    gettheAddress = ""
    try:
        gettheAddress = socket.getfqdn(domainIP)
        # gettheAddress = socket.gethostbyaddr(domainIP)

    except Exception:
        gettheAddress = None

    if gettheAddress == domainIP:
        gettheAddress = None
    return gettheAddress


def reverseLookup(ip):
    """Perform the reverse lookup."""
    api = "at_k5eJoD6do4NSnXL2BY3o1e9BH1t2b"
    url = f"https://dns-history.whoisxmlapi.com/api/v1?apiKey={api}&ip={ip}"
    payload = {}
    headers = {}
    response = requests.request("GET", url, headers=headers, data=payload).json()
    roots = set()
    subs = []
    try:
        if response["size"] > 0:
            result = response["result"]
            for domain in result:
                try:
                    root = ".".join(domain["name"].rsplit(".")[-2:])
                    roots.add(root)
                    subs.append(domain["name"])
                except KeyError:
                    continue
    except Exception:
        roots = set()
        subs = []
    return subs, roots


def main():
    """Run main."""
    global __doc__
    args = docopt(__doc__)
    try:
        print("Starting new thread")

        orgs = query_orgs_rev()

        for i, org in orgs.iterrows():
            if args["ORGS"] and org["cyhy_db_name"] not in args["ORGS"]:
                continue

            print(org["name"], "- ", org["organizations_uid"])
            print("Running IPs for ", org["name"], flush=True)
            PE_conn = connect("")
            org_uid = org["organizations_uid"]
            roots = query_roots(PE_conn, org_uid)
            roots_list = []
            for i, r in roots.iterrows():
                roots_list.append(r["root_domain"])
            ips_df = query_ips(org_uid)
            print(roots_list)
            for j, ip in ips_df.iterrows():
                ip_domain_compare(ip, roots_list, org_uid)
            close(PE_conn)

    except Exception:
        print(traceback.format_exc(), flush=True)


if __name__ == "__main__":
    main()
