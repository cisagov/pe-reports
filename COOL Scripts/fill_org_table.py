"""Take org object from json and create a organization row in the database."""
# Standard Python Libraries
import json

# Third-Party Libraries
import numpy as np
import pandas as pd
from pe_db.run import (  # query_values,
    close,
    connect,
    execute_values,
    query_null_roots,
    query_orgs,
)


def fill_orgs(org_df):
    """Create a new organization in the database."""
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


def add_empty_domains(orgs_df):
    """Create an empty null and subdomain for each organization."""
    null_roots = []
    for index, org in orgs_df.iterrows():
        # print(org)
        uid = org["organizations_uid"]
        name = org["name"]

        root = {
            "organizations_uid": uid,
            "organization_name": name,
            "root_domain": "Null_Root",
            "ip_address": np.nan,
        }
        null_roots.append(root)

    roots = pd.DataFrame(null_roots)
    print(roots)
    except_clause = """ ON CONFLICT (root_domain, organizations_uid)
    DO NOTHING;"""
    conn = connect("")
    execute_values(conn, roots, "public.root_domains", except_clause)
    root_doms = query_null_roots(conn, "public.root_domains")

    null_subs = []
    for index, rt in root_doms.iterrows():
        root_uid = rt["root_domain_uid"]
        root_dom = rt["root_domain"]

        sub = {
            "sub_domain": "Null_Sub",
            "root_domain_uid": root_uid,
            "root_domain": root_dom,
        }
        null_subs.append(sub)

    subs = pd.DataFrame(null_subs)
    except_clause = """ ON CONFLICT (sub_domain, root_domain_uid)
    DO NOTHING;"""
    conn = connect("")
    execute_values(conn, subs, "public.sub_domains", except_clause)
    # sub_doms = query_values(conn, "public.sub_domains")


def main():
    """Create organization in the database based off values in linked json."""
    f = open("org_info.json")
    org_obj = json.load(f)

    org_df = pd.DataFrame(org_obj)

    # Call fill_orgs which pulls org names an cyhy db name from json to fill the orgs table
    print("filling_orgs")
    fill_orgs(org_df)
    print("querying orgs")
    # Query back the orgs to get UID
    orgs = query_orgs("")
    # Generate a Null root_domain and Null_subdomain value for each organization
    # Allowing IPs without a subdomain to be linked back to an organization
    add_empty_domains(orgs)


if __name__ == "__main__":
    main()
