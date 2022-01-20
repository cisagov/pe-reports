"""Generate subdomains for all domains for each organization."""
# Standard Python Libraries
import os

# Third-Party Libraries
import Sublist3r.sublist3r as sb
import pandas as pd
from pe_db.run import (  # close,; query_values,
    connect,
    execute_values,
    query_orgs,
    query_roots,
)
from shodan import Shodan

SHODAN_API_KEY = "<<KEY GOES HERE>>"


def run_findomain(root):
    """Run a root domain through findomain and return subdomains."""
    print(root)
    root_dom = root["root_domain"]
    root_uid = root["root_domain_uid"]
    if root_dom != "Null_Root":
        print("Finding subdomains for ", root_dom)
        process = os.popen(f"findomain -t {root_dom} -r -q")  # nosec
        subs = process.read()
        process.close()
        subs = subs.split("\n")
        subs = list(filter(None, subs))
        if subs:
            print(subs)
            sub_dom_list = []
            for sub in subs:
                sub_dict = {
                    "sub_domain": sub,
                    "root_domain_uid": root_uid,
                    "root_domain": root_dom,
                }
                sub_dom_list.append(sub_dict)
            except_clause = """ ON CONFLICT (sub_domain, root_domain_uid)
            DO NOTHING;"""
            conn = connect()
            execute_values(
                conn, pd.DataFrame(sub_dom_list), "public.sub_domains", except_clause
            )
            print("Saved sub domains for " + root_dom)
        else:
            print("No subdomains found for ", root_dom)


def run_sublist3r(root):
    """Run a domain through sublist3r and return subdomains."""
    root_dom = root["root_domain"]
    root_uid = root["root_domain_uid"]
    if root_dom != "Null_Root":
        print("Finding subdomains for ", root_dom)
        subs = sb.main(
            root_dom,
            40,
            None,
            ports=None,
            silent=False,
            verbose=False,
            enable_bruteforce=False,
            engines=None,
        )
        subs = list(filter(None, subs))
        if subs:
            print(subs)
            sub_dom_list = []
            for sub in subs:
                sub_dict = {
                    "sub_domain": sub,
                    "root_domain_uid": root_uid,
                    "root_domain": root_dom,
                }
                sub_dom_list.append(sub_dict)
            except_clause = """ ON CONFLICT (sub_domain, root_domain_uid)
            DO NOTHING;"""
            conn = connect()
            execute_values(
                conn, pd.DataFrame(sub_dom_list), "public.sub_domains", except_clause
            )
            print("Saved sub domains for " + root_dom)
        else:
            print("No subdomains found for ", root_dom)


def run_shodan(root):
    """Run a domain through Shodan to enumerate subdomains."""
    api = Shodan(SHODAN_API_KEY)
    # root_dom = root["root_domain"]
    # root_uid = root["root_domain_uid"]

    domains = api.dns.domain_info(domain=root, history=False, type=None, page=1)
    print(domains)


def main():
    """Query root domains for each org and run them through subdomain enumerators and save results to database."""
    orgs = query_orgs()

    conn = connect()

    roots_list = []
    for i, org in orgs.iterrows():
        print("Finding Subdomains for " + org["name"])
        roots = query_roots(conn, org["organizations_uid"])

        for i, r in roots.iterrows():
            roots_list.append(r)

        print("list length ", len(roots_list))

    # Run all root domains through sublist3r
    for root in roots_list:
        run_sublist3r(root)


# Run all roots through findomain
# pool = mp.Pool(mp.cpu_count())
# pool.map(run_findomain, roots_list)
# pool.close()
# pool.join()  # block at this line until all processes are done

# Currently shodna domain lister isn't working, need to reach out to them to get this scan working
# run_shodan(roots_list)
# print("completed")


if __name__ == "__main__":
    main()
