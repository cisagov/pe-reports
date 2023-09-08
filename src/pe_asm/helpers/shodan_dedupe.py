#!/usr/bin/env python
"""Shodan dedupe script."""
# Standard Python Libraries
import hashlib
import logging
import time

# Third-Party Libraries
import pandas as pd
import shodan

# cisagov Libraries
from pe_asm.data.cyhy_db_query import (
    pe_db_connect,
    pe_db_staging_connect,
    query_cidrs_by_org,
    query_floating_ips,
    query_pe_report_on_orgs,
    update_shodan_ips,
)
from pe_source.data.pe_db.config import shodan_api_init

LOGGER = logging.getLogger(__name__)

states = [
    "AL",
    "AK",
    "AZ",
    "AR",
    "CA",
    "CO",
    "CT",
    "DC",
    "DE",
    "FL",
    "GA",
    "HI",
    "ID",
    "IL",
    "IN",
    "IA",
    "KS",
    "KY",
    "LA",
    "ME",
    "MD",
    "MA",
    "MI",
    "MN",
    "MS",
    "MO",
    "MT",
    "NE",
    "NV",
    "NH",
    "NJ",
    "NM",
    "NY",
    "NC",
    "ND",
    "OH",
    "OK",
    "OR",
    "PA",
    "RI",
    "SC",
    "SD",
    "TN",
    "TX",
    "UT",
    "VT",
    "VA",
    "WA",
    "WV",
    "WI",
    "WY",
]
state_names = [
    "Alaska",
    "Alabama",
    "Arkansas",
    "American Samoa",
    "Arizona",
    "California",
    "Colorado",
    "Connecticut",
    "Delaware",
    "Florida",
    "Georgia",
    "Guam",
    "Hawaii",
    "Iowa",
    "Idaho",
    "Illinois",
    "Indiana",
    "Kansas",
    "Kentucky",
    "Louisiana",
    "Massachusetts",
    "Maryland",
    "Maine",
    "Michigan",
    "Minnesota",
    "Missouri",
    "Mississippi",
    "Montana",
    "North Carolina",
    "North Dakota",
    "Nebraska",
    "New Hampshire",
    "New Jersey",
    "New Mexico",
    "Nevada",
    "New York",
    "Ohio",
    "Oklahoma",
    "Oregon",
    "Pennsylvania",
    "Puerto Rico",
    "Rhode Island",
    "South Carolina",
    "South Dakota",
    "Tennessee",
    "Texas",
    "Utah",
    "Virginia",
    "Virgin Islands",
    "Vermont",
    "Washington",
    "Wisconsin",
    "West Virginia",
    "Wyoming",
]


def state_check(host_org):
    """Check state."""
    found = False
    if host_org:
        for state in state_names:
            if state in host_org:
                return state
    return found


def cidr_dedupe(cidrs, api, org_type, conn):
    """Dedupe CIDR."""
    ip_obj = []
    results = []
    for cidr_index, cidr in cidrs.iterrows():
        query = f"net:{cidr['network']}"
        result = search(api, query, ip_obj, cidr["cidr_uid"], org_type)
        results.append(result)
    found = len([i for i in results if i != 0])
    LOGGER.info(f"CIDRs with IPs found: {found}")
    new_ips = pd.DataFrame(ip_obj)
    if len(new_ips) > 0:
        new_ips = new_ips.drop_duplicates(subset="ip", keep="first")
        update_shodan_ips(conn, new_ips)


def ip_dedupe(api, ips, agency_type, conn):
    """Count number of IPs with data on Shodan."""
    matched = 0
    ips = list(ips)
    float_ips = []
    for i in range(int(len(ips) / 100) + 1):
        if (i + 1) * 100 > len(ips):
            try:
                hosts = api.host(ips[i * 100 : len(ips)])
            except shodan.exception.APIError:
                try:
                    time.sleep(2)
                    hosts = api.host(ips[i * 100 : len(ips)])
                except Exception:
                    LOGGER.error(f"{i} failed again")
                    continue
            except shodan.APIError as e:
                LOGGER.error("Error: {}".format(e))
        else:
            try:
                hosts = api.host(ips[i * 100 : (i + 1) * 100])
            except shodan.exception.APIError:
                time.sleep(2)
                try:
                    hosts = api.host(ips[i * 100 : (i + 1) * 100])
                except shodan.APIError as err:
                    print("Error: {}".format(err))
                    continue
        if isinstance(hosts, list):
            for h in hosts:
                state = state_check(h["org"])
                hash_object = hashlib.sha256(str(h["ip_str"]).encode("utf-8"))
                ip_hash = hash_object.hexdigest()
                if state and agency_type == "FEDERAL":
                    continue
                else:
                    float_ips.append(
                        {
                            "ip_hash": ip_hash,
                            "ip": h["ip_str"],
                            "shodan_results": True,
                            "origin_cidr": None,
                            "current": True,
                        }
                    )
        else:
            state = state_check(hosts["org"])
            hash_object = hashlib.sha256(str(hosts["ip_str"]).encode("utf-8"))
            ip_hash = hash_object.hexdigest()
            if state and agency_type == "FEDERAL":
                continue
            else:
                float_ips.append(
                    {
                        "ip_hash": ip_hash,
                        "ip": hosts["ip_str"],
                        "shodan_results": True,
                        "origin_cidr": None,
                        "current": True,
                    }
                )
        matched = matched + len(hosts)
    new_ips = pd.DataFrame(float_ips)
    if len(new_ips) > 0:
        new_ips = new_ips.drop_duplicates(subset="ip", keep="first")
        update_shodan_ips(conn, new_ips)


def search(api, query, ip_obj, cidr_uid, org_type):
    """Search Shodan API using query and add IPs to set."""
    # Wrap the request in a try/ except block to catch errors
    try:
        LOGGER.info(query)
        # Search Shodan
        try:
            results = api.search(query)
        except shodan.exception.APIError:
            time.sleep(2)
            results = api.search(query)
        # Show the results
        for result in results["matches"]:
            # if ":" in result["ip_str"]:
            #     print("ipv6 found ", result["ip_str"])
            #     ip_type = "ipv6"
            # else:
            #     ip_type = "ipv4"
            state = state_check(result["org"])
            hash_object = hashlib.sha256(str(result["ip_str"]).encode("utf-8"))
            ip_hash = hash_object.hexdigest()
            if state and org_type == "FEDERAL":
                continue
            else:
                ip_obj.append(
                    {
                        "ip_hash": ip_hash,
                        "ip": result["ip_str"],
                        "shodan_results": True,
                        "origin_cidr": cidr_uid,
                        "current": True,
                    }
                )
        i = 1
        while i < results["total"] / 100:
            try:
                # Search Shodan
                try:
                    results = api.search(query=query, page=i)
                except shodan.exception.APIError:
                    time.sleep(2)
                    results = api.search(query, page=i)
                # Show the results
                for result in results["matches"]:
                    # if ":" in result["ip_str"]:
                    #     print("ipv6 found ", result["ip_str"])
                    #     ip_type = "ipv6"
                    # else:
                    #     ip_type = "ipv4"
                    state = state_check(result["org"])
                    hash_object = hashlib.sha256(str(result["ip_str"]).encode("utf-8"))
                    ip_hash = hash_object.hexdigest()
                    if state and org_type == "FEDERAL":
                        continue
                    else:
                        ip_obj.append(
                            {
                                "ip_hash": ip_hash,
                                "ip": result["ip_str"],
                                "shodan_results": True,
                                "origin_cidr": cidr_uid,
                                "current": True,
                            }
                        )
                i = i + 1
            except shodan.APIError as e:
                LOGGER.error("Error: {}".format(e))
                LOGGER.error(query)
                results = {"total": 0}
    except shodan.APIError as e:
        LOGGER.error("Error: {}".format(e))
        # IF it breaks to here it fails
        LOGGER.error(f"Failed on {query}")
        return 0
    return results["total"]


def dedupe(staging, orgs_df=None):
    """Check list of IPs, CIDRs, ASNS, and FQDNs in Shodan and output set of IPs."""
    # Connect to database
    if staging:
        conn = pe_db_staging_connect()
    else:
        conn = pe_db_connect()

    # Get P&E organizations DataFrame
    if not isinstance(orgs_df, pd.DataFrame):
        orgs_df = query_pe_report_on_orgs(conn)
    num_orgs = len(orgs_df.index)

    # Close database connection
    conn.close()

    # Get Shodan key from config file
    api = shodan_api_init()[0]

    # Loop through orgs
    org_count = 0
    for org_index, org in orgs_df.iterrows():
        # Connect to database
        if staging:
            conn = pe_db_staging_connect()
        else:
            conn = pe_db_connect()
        LOGGER.info(
            "Running on %s. %d/%d complete.",
            org["cyhy_db_name"],
            org_count,
            num_orgs,
        )
        # Query CIDRS
        cidrs = query_cidrs_by_org(conn, org["organizations_uid"])
        LOGGER.info(f"{len(cidrs)} cidrs found")

        # Run cidr dedupe if there are CIDRs
        if len(cidrs) > 0:
            cidr_dedupe(cidrs, api, org["agency_type"], conn)

        # Get IPs related to current sub-domains
        LOGGER.info("Grabbing floating IPs")
        ips = query_floating_ips(conn, org["organizations_uid"])
        LOGGER.info("Got Ips")
        if len(ips) > 0:
            LOGGER.info("Running dedupe on IPs")
            ip_dedupe(api, ips, org["agency_type"], conn)
        LOGGER.info("Finished dedupe")

        org_count += 1
        conn.close()


def main():
    """Run all orgs net assets through the dedupe process."""
    dedupe(False)


if __name__ == "__main__":
    main()
