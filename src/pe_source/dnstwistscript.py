"""Use DNS twist to fuzz domain names and cross check with a blacklist."""
# Standard Python Libraries
import datetime
import json
import logging
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


def checkBlocklist(dom, sub_domain_uid, source_uid, pe_org_uid, perm_list):
    """Cross reference the dnstwist results with DShield Blocklist."""
    malicious = False
    attacks = 0
    reports = 0
    if "original" in dom["fuzzer"]:
        LOGGER.info("original")
        LOGGER.info(dom["fuzzer"])
        return
    if "dns_a" not in dom:
        return
    else:
        LOGGER.info(str(dom["dns_a"][0]))
        # check IP in Blocklist API
        response = requests.get(
            "http://api.blocklist.de/api.php?ip=" + str(dom["dns_a"][0])
        ).content

        if str(response) != "b'attacks: 0<br />reports: 0<br />'":
            malicious = True
            attacks = int(str(response).split("attacks: ")[1].split("<")[0])
            reports = int(str(response).split("reports: ")[1].split("<")[0])

        # Check dns-a record in DSheild API
        if str(dom["dns_a"][0]) == "!ServFail":
            return

        results = dshield.ip(str(dom["dns_a"][0]), return_format=dshield.JSON)
        results = json.loads(results)
        try:
            threats = results["ip"]["threatfeeds"]
            attacks = results["ip"]["attacks"]
            attacks = int(0 if attacks is None else attacks)
            malicious = True
            dshield_attacks = attacks
            dshield_count = len(threats)
        except KeyError:
            dshield_attacks = 0
            dshield_count = 0

    if "ssdeep_score" not in dom:
        dom["ssdeep_score"] = ""
    if "dns_mx" not in dom:
        dom["dns_mx"] = [""]
    if "dns_ns" not in dom:
        dom["dns_ns"] = [""]
    if "dns_aaaa" not in dom:
        dom["dns_aaaa"] = [""]
    else:
        LOGGER.info(str(dom["dns_aaaa"][0]))
        # check IP in Blocklist API
        response = requests.get(
            "http://api.blocklist.de/api.php?ip=" + str(dom["dns_aaaa"][0])
        ).content
        if str(response) != "b'attacks: 0<br />reports: 0<br />'":
            malicious = True
            attacks = int(str(response).split("attacks: ")[1].split("<")[0])
            reports = int(str(response).split("reports: ")[1].split("<")[0])

        # check dns-a record in DSheild API
        if str(dom["dns_aaaa"][0]) == "!ServFail":
            return
        results = dshield.ip(str(dom["dns_aaaa"][0]), return_format=dshield.JSON)
        results = json.loads(results)

        try:
            threats = results["ip"]["threatfeeds"]
            attacks = results["ip"]["attacks"]
            attacks = int(0 if attacks is None else attacks)
            malicious = True
            dshield_attacks = attacks
            dshield_count = len(threats)
        except KeyError:
            dshield_attacks = 0
            dshield_count = 0

    # Ignore duplicates
    permutation = dom["domain"]
    LOGGER.info(permutation)
    if permutation in perm_list:
        return
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
    LOGGER.info(domain_dict)
    return domain_dict, perm_list


def run_dnstwist(root_domain, test=0):
    """Run dnstwist on each root domain."""
    pathtoDict = str(pathlib.Path(__file__).parent.resolve()) + "/common_tlds.dict"
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
            LOGGER.info(dom["domain"])
            secondlist = dnstwist.run(
                registered=True,
                tld="common_tlds.dict",
                format="json",
                threads=8,
                domain=dom["domain"],
            )
            finalorglist += secondlist
    logging.debug(finalorglist)


def main():
    """Connect to PostgreSQL database."""
    try:
        PE_conn = connect()
    except Exception:
        LOGGER.error("There was a problem logging into the psycopg database")

    source_uid = getDataSource(PE_conn, "DNSTwist")[0]
    LOGGER.info("source_uid")
    LOGGER.info(source_uid)

    """ Get P&E Orgs """
    orgs = query_orgs_rev()
    LOGGER.info(orgs["name"])

    failures = []
    for org_index, org_row in orgs.iterrows():
        pe_org_uid = org_row["organizations_uid"]
        org_name = org_row["name"]

        LOGGER.info(pe_org_uid)
        LOGGER.info(org_name)

        """Collect DNSTwist data from Crossfeed"""
        try:
            # Get root domains
            rd_df = org_root_domains(PE_conn, pe_org_uid)
            LOGGER.info(rd_df)
            domain_list = []
            perm_list = []
            for i, row in rd_df.iterrows():
                root_domain = row["root_domain"]
                if root_domain == "Null_Root":
                    continue
                LOGGER.info(row["root_domain"])

                finalorglist = run_dnstwist(root_domain)

                # Get subdomain uid
                sub_domain = root_domain
                LOGGER.info(sub_domain)
                try:
                    sub_domain_uid = getSubdomain(PE_conn, sub_domain)[0]
                    LOGGER.info(sub_domain_uid)
                except Exception:
                    # TODO Issue #265 implement custom Exceptions
                    LOGGER.info("Unable to get sub domain uid", "warning")
                    # Add and then get it
                    addSubdomain(PE_conn, sub_domain, pe_org_uid, org_name)
                    sub_domain_uid = getSubdomain(PE_conn, sub_domain)[0]

                for dom in finalorglist:
                    domain_dict, perm_list = checkBlocklist(
                        dom, sub_domain_uid, source_uid, pe_org_uid, perm_list
                    )
                    domain_list.append(domain_dict)
        except Exception:
            # TODO Issue #265 create custom Exceptions
            LOGGER.info("Failed selecting DNSTwist data.", "Warning")
            failures.append(org_name)
            LOGGER.info(traceback.format_exc())
        """Insert cleaned data into PE database."""
        try:
            cursor = PE_conn.cursor()
            try:
                columns = domain_list[0].keys()
            except Exception:
                logging.critical("No data in the domain list.")
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
            # TODO Issue #265 create custom Exceptions
            LOGGER.info("Failure inserting data into database.")
            failures.append(org_name)
            LOGGER.info(traceback.format_exc())

    if failures != []:
        LOGGER.error("These orgs failed:")
        LOGGER.error(failures)

    PE_conn.close()
