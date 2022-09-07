"""Shodan dedupe script."""
# Standard Python Libraries
import hashlib
import time

# Third-Party Libraries
import pandas as pd
import shodan
import logging

# cisagov Libraries
from pe_reports.data.db_query import close, connect, execute_values, get_orgs_df

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


def query_floating_ips(conn, org_id):
    """Query floating IPs."""
    sql = """
    SELECT i.ip
    FROM ips i
    join ips_subs ip_s on ip_s.ip_hash = i.ip_hash
    join sub_domains sd on sd.sub_domain_uid = ip_s.sub_domain_uid
    join root_domains rd on rd.root_domain_uid = sd.root_domain_uid
    WHERE rd.organizations_uid = %(org_id)s
    AND i.origin_cidr is null;
    """
    df = pd.read_sql(sql, conn, params={"org_id": org_id})
    ips = set(df["ip"])
    conn.close()
    return ips


def query_cidrs(conn, org_id):
    """Query Cidr."""
    print(org_id)
    sql = """
    SELECT network, cidr_uid
    FROM cidrs ct
    join organizations o on o.organizations_uid = ct.organizations_uid
    WHERE o.organizations_uid = %(org_id)s;
    """
    df = pd.read_sql(sql, conn, params={"org_id": org_id})
    conn.close()
    return df


def cidr_dedupe(cidrs, api, org_type):
    """Dedupe CIDR."""
    ip_obj = []
    results = []
    for i, cidr in cidrs.iterrows():
        query = f"net:{cidr['network']}"
        result = search(api, query, ip_obj, cidr["cidr_uid"], org_type)
        results.append(result)
    found = len([i for i in results if i != 0])
    logging.info(f"CIDRs with IPs found: {found}")
    new_ips = pd.DataFrame(ip_obj)
    if len(new_ips) > 0:
        new_ips = new_ips.drop_duplicates(subset="ip", keep="first")
        conn = connect()
        except_clause = """ ON CONFLICT (ip)
                    DO
                    UPDATE SET shodan_results = EXCLUDED.shodan_results"""
        execute_values(conn, new_ips, "public.ips", except_clause)
        close(conn)


def ip_dedupe(api, ips, agency_type):
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
                    logging.error(f"{i} failed again")
                    continue
            except shodan.APIError as e:
                logging.error("Error: {}".format(e))
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
                    float_ips.append(
                        {
                            "ip_hash": ip_hash,
                            "ip": h["ip_str"],
                            "shodan_results": False,
                            "origin_cidr": None,
                        }
                    )
                else:
                    float_ips.append(
                        {
                            "ip_hash": ip_hash,
                            "ip": h["ip_str"],
                            "shodan_results": True,
                            "origin_cidr": None,
                        }
                    )
        else:
            state = state_check(hosts["org"])
            hash_object = hashlib.sha256(str(hosts["ip_str"]).encode("utf-8"))
            ip_hash = hash_object.hexdigest()
            if state and agency_type == "FEDERAL":
                float_ips.append(
                    {
                        "ip_hash": ip_hash,
                        "ip": hosts["ip_str"],
                        "shodan_results": False,
                        "origin_cidr": None,
                    }
                )
            else:
                float_ips.append(
                    {
                        "ip_hash": ip_hash,
                        "ip": hosts["ip_str"],
                        "shodan_results": True,
                        "origin_cidr": None,
                    }
                )
        matched = matched + len(hosts)
    new_ips = pd.DataFrame(float_ips)
    if len(new_ips) > 0:
        new_ips = new_ips.drop_duplicates(subset="ip", keep="first")
        conn = connect()
        except_clause = """ ON CONFLICT (ip)
                    DO
                    UPDATE SET shodan_results = EXCLUDED.shodan_results"""
        execute_values(conn, new_ips, "public.ips", except_clause)
        close(conn)


def search(api, query, ip_obj, cidr_uid, org_type):
    """Search Shodan API using query and add IPs to set."""
    # Wrap the request in a try/ except block to catch errors
    try:
        logging.info(query)
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
                ip_obj.append(
                    {
                        "ip_hash": ip_hash,
                        "ip": result["ip_str"],
                        "shodan_results": False,
                        "origin_cidr": cidr_uid,
                    }
                )
            else:
                ip_obj.append(
                    {
                        "ip_hash": ip_hash,
                        "ip": result["ip_str"],
                        "shodan_results": True,
                        "origin_cidr": cidr_uid,
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
                        ip_obj.append(
                            {
                                "ip_hash": ip_hash,
                                "ip": result["ip_str"],
                                "shodan_results": False,
                                "origin_cidr": cidr_uid,
                            }
                        )
                    else:
                        ip_obj.append(
                            {
                                "ip_hash": ip_hash,
                                "ip": result["ip_str"],
                                "shodan_results": True,
                                "origin_cidr": cidr_uid,
                            }
                        )
                i = i + 1
            except shodan.APIError as e:
                logging.error("Error: {}".format(e))
                logging.error(query)
                results = {"total": 0}
    except shodan.APIError as e:
        logging.error("Error: {}".format(e))
        # IF it breaks to here it fails
        logging.error(f"Failed on {query}")
        return 0
    return results["total"]


def dedupe(orgs):
    """Check list of IPs, CIDRs, ASNS, and FQDNs in Shodan and output set of IPs."""
    # get username and password from config file
    # TODO: Add key
    key = ""
    api = shodan.Shodan(key)
    for i, org in orgs.iterrows():

        logging.info(f"Running on {org['name']}")
        conn = connect()
        cidrs = query_cidrs(conn, org["organizations_uid"])
        logging.info(f"{len(cidrs)} cidrs found")
        if len(cidrs) > 0:
            cidr_dedupe(cidrs, api, org["agency_type"])
        conn = connect()
        logging.info("Grabbing floating IPs")
        ips = query_floating_ips(conn, org["organizations_uid"])
        logging.info("Got Ips")
        if len(ips) > 0:
            logging.info("Running dedupe on IPs")
            ip_dedupe(api, ips, org["agency_type"])
        logging.info("Finished dedupe")


def main():
    orgs = get_orgs_df()
    orgs = orgs[orgs["report_on"] == True]
    print(orgs)

    dedupe(orgs)


if __name__ == "__main__":
    main()
