"""Run an organizations CIDRs through shodan and extract IPs that have returned results and add them to the db."""
# !/usr/bin/ python3
# -*- coding: utf-8 -*-
# Standard Python Libraries
import time

# Third-Party Libraries
import pandas as pd
from pe_db.run import connect, execute_values, query_orgs, query_web_assets
import shodan

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
    """Check if a state name appears in the name of the organization name."""
    found = False
    if host_org:
        for state in state_names:
            if state in host_org:
                return state
    return found


def search(api, query, ip_obj, org_uid):
    """Search Shodan API using query and add IPs to set."""
    # Wrap the request in a try/ except block to catch errors
    try:
        # Search Shodan
        try:
            results = api.search(query)
        except shodan.exception.APIError:
            time.sleep(2)
            results = api.search(query)
        # Show the results
        for result in results["matches"]:
            if ":" in result["ip_str"]:
                print("ipv6 found ", result["ip_str"])
                ip_type = "ipv6"
            else:
                ip_type = "ipv4"
            state = state_check(result["org"])
            if state:
                ip_obj.append(
                    {
                        "asset_type": ip_type,
                        "asset": result["ip_str"],
                        "organizations_uid": org_uid,
                        "asset_origin": "Shodan-state-in-org",
                        "report_on": False,
                    }
                )
            else:
                ip_obj.append(
                    {
                        "asset_type": ip_type,
                        "asset": result["ip_str"],
                        "organizations_uid": org_uid,
                        "asset_origin": "Shodan",
                        "report_on": True,
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
                    if ":" in result["ip_str"]:
                        print("ipv6 found ", result["ip_str"])
                        ip_type = "ipv6"
                    else:
                        ip_type = "ipv4"
                    state = state_check(result["org"])
                    if state:
                        ip_obj.append(
                            {
                                "asset_type": ip_type,
                                "asset": result["ip_str"],
                                "organizations_uid": org_uid,
                                "asset_origin": "Shodan-state-in-org",
                                "report_on": False,
                            }
                        )
                    else:
                        ip_obj.append(
                            {
                                "asset_type": ip_type,
                                "asset": result["ip_str"],
                                "organizations_uid": org_uid,
                                "asset_origin": "Shodan",
                                "report_on": True,
                            }
                        )
                i = i + 1
            except shodan.APIError as e:
                print("Error: {}".format(e))
                print(query)
                results = {"total": 0}
    except shodan.APIError as e:
        print("Error: {}".format(e))
        # IF it breaks to here it fails
        print(f"Failed on {query}")
        return 0

    return results["total"]


def bulk_ip_lookup(api, ips, org_uid):
    """Count number of IPs with data on Shodan."""
    matched = 0
    ips = list(ips)
    state_ips = []
    for i in range(int(len(ips) / 100) + 1):
        if (i + 1) * 100 > len(ips):
            try:
                hosts = api.host(ips[i * 100 : len(ips)])
            except shodan.exception.APIError:
                try:
                    time.sleep(2)
                    hosts = api.host(ips[i * 100 : len(ips)])
                # This except may need to be adjusted
                except shodan.exception.APIError:
                    print(f"{i} failed again")
                    continue
            except shodan.APIError as e:
                print("Error: {}".format(e))
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
                if state:
                    state_ips.append(
                        {
                            "asset_type": "ipv4",
                            "asset": h["ip_str"],
                            "organizations_uid": org_uid,
                            "asset_origin": "-state-in-org",
                            "report_on": False,
                        }
                    )

        else:
            state = state_check(hosts["org"])
            if state:
                state_ips.append(
                    {
                        "asset_type": "ipv4",
                        "asset": h["ip_str"],
                        "organizations_uid": org_uid,
                        "asset_origin": "-state-in-org",
                        "report_on": False,
                    }
                )
        matched = matched + len(hosts)
    print(state_ips)
    print(f"IPs matched in Shodan: {matched}")
    return state_ips


def parse_file(in_df):
    """Separate input csv into IPs, CIDRs, ASNs, and FQDNs and return lists."""
    ip_df = in_df[in_df["type"] == "ipv4"]
    n_ip = len(ip_df)
    print(f"IPs : {n_ip}")
    cidr_df = in_df[in_df["type"].str.contains("cidr", na=False)]
    n_cidr = len(cidr_df)
    print(f"CIDRs : {n_cidr}")
    asn_df = in_df[in_df["type"] == "asn"]
    n_asn = len(asn_df)
    print(f"ASNs : {n_asn}")
    fqdn_df = in_df[in_df["type"] == "fqdn"]
    n_fqdn = len(fqdn_df)
    print(f"FQDNs : {n_fqdn}")

    ips = set(ip_df["name"])
    cidrs = set(cidr_df["name"])
    asns = set(asn_df["name"])
    fqdns = set(fqdn_df["name"])

    return ips, cidrs, asns, fqdns


def check_cidrs(api, ip_obj, cidrs, org_uid):
    """Check IPs found within CIDR block against existing set of IPs."""
    results = []
    for cidr in cidrs:
        query = f"net:{cidr}"
        result = search(api, query, ip_obj, org_uid)
        results.append(result)
    found = len([i for i in results if i != 0])
    print(f"CIDRs with IPs found: {found}")


def check_asns(api, ip_obj, asns, org_uid):
    """Check IPs found within ASN block against existing set of IPs."""
    results = []
    for asn in asns:
        query = f"asn:AS{asn}"
        result = search(api, query, ip_obj, org_uid)
        results.append(result)
    found = len([i for i in results if i != 0])
    print(f"ASNs with IPs found: {found}")


def check_fqdns(api, ip_obj, fqdns, org_uid):
    """Check IPs with field containing FQDN string against existing set of IPs."""
    results = []
    for fqdn in fqdns:
        result = search(api, fqdn, ip_obj, org_uid)
        results.append(result)
    found = len([i for i in results if i != 0])
    print(f"FQDNs with IPs found: {found}")


def dedupe(api, in_df, org_uid):
    """Compare IPs to IPs on Shodan from CIDRs/ASNs/FQDNs and output to csv."""
    ip_obj = []
    ips, cidrs, asns, fqdns = parse_file(in_df)
    if len(ips) > 0:
        state_ips = bulk_ip_lookup(api, ips, org_uid)
    else:
        state_ips = pd.DataFrame(
            columns=[
                "asset_type",
                "asset",
                "organizations_uid",
                "asset_origin",
                "report_on",
            ]
        )
    if len(cidrs) > 0:
        check_cidrs(api, ip_obj, cidrs, org_uid)
    print(len(ip_obj))
    if len(asns) > 0:
        check_asns(api, ip_obj, asns, org_uid)
    print(len(ip_obj))
    if len(fqdns) > 0:
        check_fqdns(api, ip_obj, fqdns, org_uid)
    print(len(ip_obj))
    new_ips = pd.DataFrame(ip_obj)
    state_ips = pd.DataFrame(state_ips)
    print(state_ips.head())
    print(new_ips.head())
    if len(state_ips) > 0:
        state_ips = state_ips.drop_duplicates(subset="asset", keep="first")
        conn = connect("")
        except_clause = """ ON CONFLICT (asset, organizations_uid)
                    DO
                    UPDATE SET report_on = EXCLUDED.report_on , asset_origin = web_assets.asset_origin || EXCLUDED.asset_origin ;"""
        execute_values(conn, state_ips, "public.web_assets", except_clause)
    if len(new_ips) > 0:
        new_ips = new_ips.drop_duplicates(subset="asset", keep="first")
        conn = connect("")
        except_clause = """ ON CONFLICT (asset, organizations_uid)
                    DO
                    UPDATE SET report_on = EXCLUDED.report_on"""
        execute_values(conn, new_ips, "public.web_assets", except_clause)


def main():
    """Check list of IPs, CIDRs, ASNS, and FQDNs in Shodan and output set of IPs."""
    global __doc__

    # __doc__ = re.sub('COMMAND_NAME', __file__, __doc__)
    # args = docopt(__doc__, version='v2.0')

    # get username and password from config file
    key = "sllF7xRbj5HsIqiOUcx9RUF22z41Rpq7"
    api = shodan.Shodan(key)

    # id = args['ORG_ID']
    # in_df = pd.read_csv(f'/Users/jensend/Projects/Testing/cyhy_ips/{id}.csv')
    # in_df['type'] = 'cidrv4'
    # in_df = in_df.rename(columns={'ips':'name'})

    # in_df = in_df[['type','name']]
    # lg_df = pd.read_csv(f'/Users/jensend/Projects/Testing/LG_elements/members-{id}.csv')
    # lg_df = lg_df[['type','name']]
    # cmbo_df =(pd.concat([in_df, lg_df], ignore_index=True, sort =False)
    #     .drop_duplicates(['type','name'], keep='last'))
    # cmbo_df = cmbo_df.reset_index()

    # diff = (len(lg_df) + len(in_df) ) - len(cmbo_df)
    # print(f'{diff} duplicates in dataframes')
    # cmbo_df
    # out_file = f'cyhy_final/{id}.csv'
    orgs = query_orgs("")

    for i, org in orgs.iterrows():
        if org["cyhy_db_name"] in ["DHS_TSA", "DOL_BLS", "HHS_NIH"]:
            conn = connect("")
            assets = query_web_assets(conn, org["organizations_uid"])
            print(assets)
            assets = assets[["asset_type", "asset"]]
            assets = assets.rename(columns={"asset_type": "type", "asset": "name"})
            print(assets)

            dedupe(api, assets, org["organizations_uid"])


if __name__ == "__main__":
    main()
