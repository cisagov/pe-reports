"""Use dnstwist to fuzz domain names and cross check with a blocklist."""
# Standard Python Libraries
import datetime
import json
import pathlib
import traceback

# Third-Party Libraries
import dnstwist
import dshield
import psycopg2.extras as extras
import requests

# cisagov Libraries
from pe_reports import app

from .data.pe_db.db_query_source import (
    addSubdomain,
    connect,
    getDataSource,
    getSubdomain,
    org_root_domains,
    query_orgs_rev,
)

date = datetime.datetime.now().strftime("%Y-%m-%d")
LOGGER = app.config["LOGGER"]


def checkBlocklist(
    dom, sub_domain_uid, source_uid, pe_org_uid, perm_list, test_flag=False
):
    """Cross reference the dnstwist results with DShield blocklist."""
    malicious = False
    attacks = 0
    reports = 0
    if "original" in dom["fuzzer"] or "dns_a" not in dom:
        return None, perm_list
    else:
        domain_a = str(dom["dns_a"][0])
        if domain_a == "!ServFail":
            return None, perm_list
        LOGGER.info(domain_a)

        # Check IP in blocklist.de API, if tetsing is true, for testing purposes skip this one as it may go offline
        if not test_flag:
            response = requests.get(
                "http://api.blocklist.de/api.php?ip=" + domain_a
            ).content

            if str(response) != "b'attacks: 0<br />reports: 0<br />'":
                malicious = True
                attacks = int(str(response).split("attacks: ")[1].split("<")[0])
                reports = int(str(response).split("reports: ")[1].split("<")[0])

        # Check IP in DShield API
        try:
            results = json.loads(dshield.ip(domain_a, return_format=dshield.JSON))
            threats = results["ip"]["threatfeeds"]
            dshield_attacks = int(results["ip"].get("attacks", 0))
            malicious = True
            dshield_count = len(threats)
        except KeyError:
            dshield_attacks = 0
            dshield_count = 0

    # Check IPv6
    if "dns_aaaa" not in dom:
        dom["dns_aaaa"] = [""]
    elif str(dom["dns_aaaa"][0]) == "!ServFail":
        dom["dns_aaaa"] = [""]
    else:
        domain_aaaa = str(dom["dns_aaaa"][0])

        if not test_flag:
            # Check IP in Blocklist API
            response = requests.get(
                "http://api.blocklist.de/api.php?ip=" + domain_aaaa
            ).content

            if str(response) != "b'attacks: 0<br />reports: 0<br />'":
                malicious = True
                attacks = int(str(response).split("attacks: ")[1].split("<")[0])
                reports = int(str(response).split("reports: ")[1].split("<")[0])

        try:
            results = json.loads(dshield.ip(domain_aaaa, return_format=dshield.JSON))
            threats = results["ip"]["threatfeeds"]
            dshield_attacks = int(results["ip"].get("attacks", 0))
            malicious = True
            dshield_count = len(threats)
        except KeyError:
            dshield_attacks = 0
            dshield_count = 0

    # Clean-up other fields
    if "ssdeep_score" not in dom:
        dom["ssdeep_score"] = ""
    if "dns_mx" not in dom:
        dom["dns_mx"] = [""]
    if "dns_ns" not in dom:
        dom["dns_ns"] = [""]

    # Ignore duplicates
    permutation = dom["domain"]
    if permutation in perm_list:
        return None, perm_list
    else:
        perm_list.append(permutation)

    domain_dict = {
        "blocklist_attack_count": attacks,
        "blocklist_report_count": reports,
        "data_source_uid": source_uid,
        "date_active": date,
        "domain_permutation": dom["domain"],
        "dshield_attack_count": dshield_attacks,
        "dshield_record_count": dshield_count,
        "fuzzer": dom["fuzzer"],
        "ipv4": domain_a,
        "ipv6": domain_aaaa,
        "mail_server": dom["dns_mx"][0],
        "malicious": malicious,
        "name_server": dom["dns_ns"][0],
        "organizations_uid": pe_org_uid,
        "ssdeep_score": dom["ssdeep_score"],
        "sub_domain_uid": sub_domain_uid,
    }
    return domain_dict, perm_list


def execute_dnstwist(root_domain, test=0):
    """Run dnstwist on each root domain."""
    pathtoDict = f"{pathlib.Path(__file__).parent.resolve()}/data/common_tlds.dict"
    dnstwist_result = dnstwist.run(
        domain=root_domain,
        format="json",
        registered=True,
        threads=8,
        tld=pathtoDict,
    )
    if test == 1:
        return dnstwist_result
    for dom in dnstwist_result.copy():
        if ("tld-swap" not in dom["fuzzer"]) and ("original" not in dom["fuzzer"]):
            LOGGER.info("Running again on %s", dom["domain"])
            dnstwist_result += dnstwist.run(
                domain=dom["domain"],
                format="json",
                registered=True,
                threads=8,
                tld=pathtoDict,
            )
    return dnstwist_result


def run_dnstwist(orgs_list):
    """Run DNStwist on certain domains and upload findings to database."""
    PE_conn = connect()
    source_uid = getDataSource(PE_conn, "DNSTwist")[0]

    """ Get P&E orgs """
    orgs = query_orgs_rev()
    failures = []
    for org_index, org_row in orgs.iterrows():
        pe_org_uid = org_row["organizations_uid"]
        org_name = org_row["name"]
        pe_org_id = org_row["cyhy_db_name"]

        # Only run on orgs in the org list
        if pe_org_id in orgs_list or orgs_list == "all":

            LOGGER.info("Running dnstwist on %s", pe_org_id)

            """Collect dnstwist data from Crossfeed"""
            try:
                # Get root domains
                rd_df = org_root_domains(PE_conn, pe_org_uid)
                domain_list = []
                perm_list = []
                for i, row in rd_df.iterrows():
                    root_domain = row["root_domain"]
                    if root_domain == "Null_Root":
                        continue
                    LOGGER.info("Running on %s", row["root_domain"])

                    finalorglist = execute_dnstwist(root_domain)

                    # Get subdomain uid
                    sub_domain = root_domain
                    try:
                        sub_domain_uid = getSubdomain(PE_conn, sub_domain)[0]
                    except Exception:
                        # TODO: Create custom exceptions.
                        # Issue 265: https://github.com/cisagov/pe-reports/issues/265
                        LOGGER.info("Unable to get sub domain uid", "warning")
                        # Add and then get it
                        addSubdomain(PE_conn, sub_domain, pe_org_uid)
                        sub_domain_uid = getSubdomain(PE_conn, sub_domain)[0]

                    for dom in finalorglist:
                        domain_dict, perm_list = checkBlocklist(
                            dom, sub_domain_uid, source_uid, pe_org_uid, perm_list
                        )
                        if domain_dict is not None:
                            domain_list.append(domain_dict)
            except Exception:
                # TODO: Create custom exceptions.
                # Issue 265: https://github.com/cisagov/pe-reports/issues/265
                LOGGER.info("Failed selecting dnstwist data.", "Warning")
                failures.append(org_name)
                LOGGER.info(traceback.format_exc())

            """Insert cleaned data into PE database."""
            try:
                cursor = PE_conn.cursor()
                try:
                    columns = domain_list[0].keys()
                except Exception:
                    LOGGER.critical("No data in the domain list.")
                    failures.append(org_name)
                    continue
                table = "domain_permutations"
                sql = """INSERT INTO {}({}) VALUES %s
                ON CONFLICT (domain_permutation,organizations_uid)
                DO UPDATE SET malicious = EXCLUDED.malicious,
                    blocklist_attack_count = EXCLUDED.blocklist_attack_count,
                    blocklist_report_count = EXCLUDED.blocklist_report_count,
                    dshield_record_count = EXCLUDED.dshield_record_count,
                    dshield_attack_count = EXCLUDED.dshield_attack_count,
                    data_source_uid = EXCLUDED.data_source_uid,
                    date_active = EXCLUDED.date_active;"""

                values = [[value for value in dict.values()] for dict in domain_list]
                extras.execute_values(
                    cursor,
                    sql.format(
                        table,
                        ",".join(columns),
                    ),
                    values,
                )
                PE_conn.commit()
                LOGGER.info("Data inserted using execute_values() successfully.")

            except Exception:
                # TODO: Create custom exceptions.
                # Issue 265: https://github.com/cisagov/pe-reports/issues/265
                LOGGER.info("Failure inserting data into database.")
                failures.append(org_name)
                LOGGER.info(traceback.format_exc())

    PE_conn.close()
    if failures != []:
        LOGGER.error("These orgs failed:")
        LOGGER.error(failures)


if __name__ == "__main__":
    run_dnstwist("all")
