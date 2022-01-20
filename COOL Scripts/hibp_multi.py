"""Run hibp for every subdomain for each organization."""

# Standard Python Libraries
import multiprocessing as mp

# Third-Party Libraries
from Reviewed.Keep.hibp_func import get_breaches, get_emails

# import numpy as np
import pandas as pd
from pe_db.run import (
    connect,
    execute_hibp_breach_values,
    execute_hibp_emails_values,
    query_orgs,
    query_values,
)

breaches = get_breaches()
conn = connect()
execute_hibp_breach_values(conn, breaches, "hibp_breaches")

breaches_resp = query_values(conn, "hibp_breaches")

breach_UIDS_Dict = {}
for i, breach in breaches_resp.iterrows():
    breach_UIDS_Dict.update({breach["breach_name"]: breach["hibp_breaches_uid"]})


def flatten_data(response, subdomain, rootdomain, organization):
    """Turn hibp response into a readable list of dictionaries."""
    combined_data = []
    # loop through the json response
    if response:
        for key, value in response.items():
            # for each email loop through the list of breaches
            for b in value:
                combined_data.append(
                    {
                        "email": key + "@" + subdomain,
                        "organizations_uid": organization,
                        "root_domain": rootdomain,
                        "sub_domain": subdomain,
                        "breach_name": b,
                        "breach_id": breach_UIDS_Dict[b],
                    }
                )
    # print(combined_data)
    return combined_data


def run_subs(sub):
    """Run each subdomain through hibp."""
    Email = []

    subs = sub["sub_domains"]
    root = sub["root_domain"]
    org = sub["organizations_uid"]
    if root != "Null_Root":
        print(f"running hibp on {root}'s {len(subs)} subdomains")
        counter = 0
        for s in subs:
            if s != "Null_Sub":

                response = get_emails(s)
                counter += 1
                Emails = flatten_data(response, s, root, org)
                Email = Email + Emails
                if counter % 500 == 0:
                    print(
                        root
                        + ": "
                        + str(counter)
                        + "/"
                        + str(len(subs))
                        + " subdomains have been run through hibp"
                    )

    exposures = pd.DataFrame(Email)
    if len(exposures) > 0:
        conn = connect()
        emails = merge_mod_date(exposures, breaches)
        print(emails)
        execute_hibp_emails_values(conn, emails, "hibp_exposed_credentials")

    return exposures


def merge_mod_date(emails, breaches):
    """Merge the emails and breaches data into one dataframe."""
    emails = pd.merge(
        emails, breaches[["breach_name", "modified_date"]], on="breach_name"
    )
    return emails


def main():
    """Run hibp on all orgs subdomains."""
    orgs = query_orgs()
    sub_dom_list = []
    for i, org in orgs.iterrows():
        org_name = org["name"]
        org_uid = org["organizations_uid"]
        print("Running HIBP on subdomains for ", org_name)
        conn = connect()
        root_doms = query_values(
            conn, "root_domains", f" WHERE organizations_uid ='{org_uid}'"
        )

        for i, root in root_doms.iterrows():
            root_uid = root["root_domain_uid"]
            root_domain = root["root_domain"]
            print("Finding subdomains for " + root_domain)

            conn = connect()
            sub_doms = query_values(
                conn, "sub_domains", f" WHERE root_domain_uid ='{root_uid}'"
            )
            subs_list = []
            for i, sub in sub_doms.iterrows():
                subs_list.append(sub["sub_domain"])

            sub_dom_obj = {
                "organizations_uid": org_uid,
                "root_domain": root_domain,
                "sub_domains": subs_list,
            }

            sub_dom_list.append(sub_dom_obj)

    #  Run all sub domains through hibp

    pool = mp.Pool(mp.cpu_count())
    pool.map(run_subs, sub_dom_list)
    pool.close()
    pool.join()


if __name__ == "__main__":
    main()
