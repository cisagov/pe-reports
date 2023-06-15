"""Use DNS twist to fuzz domain names and cross check with a blacklist."""
# Standard Python Libraries
import datetime
import json
import logging
import pathlib
import traceback
import contextlib

# Third-Party Libraries
import dnstwist
import dshield
import psycopg2.extras as extras
import requests

from .data.pe_db.db_query import (
    addSubdomain,
    connect,
    get_data_source_uid,
    getSubdomain,
    org_root_domains,
    get_orgs,
)

date = datetime.datetime.now().strftime("%Y-%m-%d")
LOGGER = logging.getLogger(__name__)


def checkBlocklist(dom, sub_domain_uid, source_uid, pe_org_uid, perm_list):
    """Cross reference the dnstwist results with DShield Blocklist."""
    malicious = False
    attacks = 0
    reports = 0
    if "original" in dom["fuzzer"]:
        return None, perm_list
    elif "dns_a" not in dom:
        return None, perm_list
    else:
        if str(dom["dns_a"][0]) == "!ServFail":
            return None, perm_list

        # Check IP in Blocklist API
        response = requests.get(
            "http://api.blocklist.de/api.php?ip=" + str(dom["dns_a"][0])
        ).content

        if str(response) != "b'attacks: 0<br />reports: 0<br />'":
            try:
                malicious = True
                attacks = int(str(response).split("attacks: ")[1].split("<")[0])
                reports = int(str(response).split("reports: ")[1].split("<")[0])
            except:
                malicious = False
                dshield_attacks = 0
                dshield_count = 0

        # Check IP in DSheild API
        try:
            results = dshield.ip(str(dom["dns_a"][0]), return_format=dshield.JSON)
            results = json.loads(results)
            threats = results["ip"]["threatfeeds"]
            attacks = results["ip"]["attacks"]
            attacks = int(0 if attacks is None else attacks)
            malicious = True
            dshield_attacks = attacks
            dshield_count = len(threats)
        except:
            dshield_attacks = 0
            dshield_count = 0

    # Check IPv6
    if "dns_aaaa" not in dom:
        dom["dns_aaaa"] = [""]
    elif str(dom["dns_aaaa"][0]) == "!ServFail":
        dom["dns_aaaa"] = [""]
    else:
        # Check IP in Blocklist API
        response = requests.get(
            "http://api.blocklist.de/api.php?ip=" + str(dom["dns_aaaa"][0])
        ).content
        if str(response) != "b'attacks: 0<br />reports: 0<br />'":
            try:
                malicious = True
                attacks = int(str(response).split("attacks: ")[1].split("<")[0])
                reports = int(str(response).split("reports: ")[1].split("<")[0])
            except:
                malicious = False
                dshield_attacks = 0
                dshield_count = 0
        try:
            results = dshield.ip(str(dom["dns_aaaa"][0]), return_format=dshield.JSON)
            results = json.loads(results)
            threats = results["ip"]["threatfeeds"]
            attacks = results["ip"]["attacks"]
            attacks = int(0 if attacks is None else attacks)
            malicious = True
            dshield_attacks = attacks
            dshield_count = len(threats)
        except:
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
        "organizations_uid": pe_org_uid,
        "data_source_uid": source_uid,
        "sub_domain_uid": sub_domain_uid,
        "domain_permutation": dom["domain"],
        "ipv4": dom["dns_a"][0],
        "ipv6": dom["dns_aaaa"][0],
        "mail_server": dom["dns_mx"][0],
        "name_server": dom["dns_ns"][0],
        "fuzzer": dom["fuzzer"],
        "date_active": date,
        "ssdeep_score": dom["ssdeep_score"],
        "malicious": malicious,
        "blocklist_attack_count": attacks,
        "blocklist_report_count": reports,
        "dshield_record_count": dshield_count,
        "dshield_attack_count": dshield_attacks,
    }
    return domain_dict, perm_list


def execute_dnstwist(root_domain, test=0):
    """Run dnstwist on each root domain."""
    pathtoDict = str(pathlib.Path(__file__).parent.resolve()) + "/data/common_tlds.dict"
    dnstwist_result = dnstwist.run(
        registered=True,
        tld=pathtoDict,
        format="json",
        threads=8,
        domain=root_domain,
    )
    if test == 1:
        return dnstwist_result
    finalorglist = dnstwist_result + []
    for dom in dnstwist_result:
        if ("tld-swap" not in dom["fuzzer"]) and ("original" not in dom["fuzzer"]):
            secondlist = dnstwist.run(
                registered=True,
                tld=pathtoDict,
                format="json",
                threads=8,
                domain=dom["domain"],
            )
            finalorglist += secondlist
    return finalorglist


def run_dnstwist(orgs_list):
    """Run DNStwist on certain domains and upload findings to database."""
    PE_conn = connect()
    source_uid = get_data_source_uid("DNSTwist")

    """ Get P&E Orgs """
    orgs = get_orgs()
    failures = []
    for org in orgs:
        pe_org_uid = org["org_uid"]
        org_name = org["org_name"]
        pe_org_id = org["cyhy_db_name"]

        # Only run on orgs in the org list
        if pe_org_id in orgs_list or orgs_list == "all":
            LOGGER.info("Running DNSTwist on %s", pe_org_id)

            """Collect DNSTwist data from Crossfeed"""
            try:
                # Get root domains
                root_dict = org_root_domains(PE_conn, pe_org_uid)
                domain_list = []
                perm_list = []
                for root in root_dict:
                    root_domain = root["root_domain"]
                    if root_domain == "Null_Root":
                        continue
                    LOGGER.info("\tRunning on root domain: %s", root["root_domain"])

                    with open(
                        "dnstwist_output.txt", "w"
                    ) as f, contextlib.redirect_stdout(f):
                        finalorglist = execute_dnstwist(root_domain)

                    # Get subdomain uid
                    sub_domain = root_domain
                    try:
                        sub_domain_uid = getSubdomain(sub_domain)
                    except Exception:
                        # TODO: Create custom exceptions.
                        # Issue 265: https://github.com/cisagov/pe-reports/issues/265
                        # Add and then get it
                        addSubdomain(PE_conn, sub_domain, pe_org_uid, True)
                        sub_domain_uid = getSubdomain(sub_domain)

                    # Check Blocklist
                    for dom in finalorglist:
                        domain_dict, perm_list = checkBlocklist(
                            dom, sub_domain_uid, source_uid, pe_org_uid, perm_list
                        )
                        if domain_dict is not None:
                            domain_list.append(domain_dict)
            except Exception:
                # TODO: Create custom exceptions.
                # Issue 265: https://github.com/cisagov/pe-reports/issues/265
                LOGGER.info("Failed selecting DNSTwist data.")
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
                LOGGER.info("Data inserted using execute_values() successfully..")

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
