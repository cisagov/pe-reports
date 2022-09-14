"""Create orgs and root domains."""
# Standard Python Libraries
import json
import socket

# Third-Party Libraries
from data.run import close, connect, execute_values, getDataSource, query_orgs
import numpy as np
import pandas as pd

source = getDataSource("dot-gov")
source_uid = source[0]


def fill_orgs(org_df):
    """Fill orgs."""
    org_table = org_df[["full_name", "cyhy_db_name"]]

    org_table.rename(
        columns={
            "full_name": "name",
        },
        inplace=True,
    )
    print(org_table)

    conn = connect("")
    except_clause = """ ON CONFLICT (name)
    DO NOTHING;"""
    execute_values(conn, org_table, "public.organizations", except_clause)

    close(conn)


def add_empty_domains(orgs_df, json_orgs):
    """Add empty domains."""
    roots_list = []
    for org_index, org in orgs_df.iterrows():
        print(org)
        # print(org)
        uid = org["organizations_uid"]
        name = org["name"]
        cyhy_db_name = org["cyhy_db_name"]
        # root = {
        #     'organizations_uid':uid,
        #     'organization_name':name,
        #     'root_domain': 'Null_Root',
        #     'ip_address': np.nan
        #  }
        # null_roots.append(root)
        current_org = json_orgs[json_orgs["cyhy_db_name"] == cyhy_db_name].head(1)
        for domain in current_org["domains"].item():
            try:
                ip = socket.gethostbyname(domain)
            except Exception:
                ip = np.nan
            root = {
                "organizations_uid": uid,
                "organization_name": name,
                "root_domain": domain,
                "ip_address": ip,
                "data_source_uid": source_uid,
            }
            roots_list.append(root)

    roots = pd.DataFrame(roots_list)
    print(roots)
    except_clause = """ ON CONFLICT (root_domain, organizations_uid)
    DO NOTHING;"""
    conn = connect("")
    execute_values(conn, roots, "public.root_domains", except_clause)
    # root_doms = query_null_roots(conn, "public.root_domains")

    # null_subs = []
    # for index, rt in root_doms.iterrows():
    #     root_uid = rt['root_domain_uid']
    #     root_dom = rt['root_domain']

    #     sub = {
    #         'sub_domain': "Null_Sub",
    #         'root_domain_uid': root_uid,
    #         'root_domain': root_dom
    #     }
    #     null_subs.append(sub)

    # subs = pd.DataFrame(null_subs)
    # except_clause = """ ON CONFLICT (sub_domain, root_domain_uid)
    # DO NOTHING;"""
    # conn = connect("")
    # execute_values(conn, subs, "public.sub_domains", except_clause)
    # sub_doms = query_values(conn, "public.sub_domains")


f = open("org_info.json")
org_obj = json.load(f)

org_df = pd.DataFrame(org_obj)
print(org_df)
# Call fill_orgs which pulls org names an cyhy db name from json to fill the orgs table
print("filling_orgs")
fill_orgs(org_df)
print("querying orgs")
# Query back the orgs to get UID
orgs = query_orgs("")
print(orgs)
# Generate a Null root_domain and Null_subdomain value for each organization
# Allowing IPs without a subdomain to be linked back to an organization
add_empty_domains(orgs, org_df)

orgs
