"""Pshtt wrapper."""
# Standard Python Libraries
# from pshtt.pshtt.utils import smart_open
# from .data.pe_db.config import config
# from .data.run import getDataSource
# Standard Python Libraries
import datetime
import json
import logging
import threading

# Third-Party Libraries
import numpy as np

# cisagov Libraries
from pshtt.pshtt import inspect_domains
import pshtt.utils as utils

from .data.pe_db.db_query import api_pshtt_domains_to_run, api_pshtt_insert

NOW = datetime.datetime.now()
DAYS_BACK = datetime.timedelta(days=15)
DAY = datetime.timedelta(days=1)
START_DATE = NOW - DAYS_BACK
END_DATE = NOW + DAY
LOGGER = logging.getLogger(__name__)


def format_pshtt_result(result, sub):
    """Format pshtt result to match api endpoint requirements."""
    result_dict = {
        "base_domain": result["Base Domain"],
        "base_domain_hsts_preloaded": result["Base Domain HSTS Preloaded"],
        "canonical_url": result["Canonical URL"],
        "defaults_to_https": result["Defaults to HTTPS"],
        "domain": result["Domain"],
        "domain_enforces_https": result["Domain Enforces HTTPS"],
        "domain_supports_https": result["Domain Supports HTTPS"],
        "domain_uses_strong_hsts": result["Domain Uses Strong HSTS"],
        "downgrades_https": result["Downgrades HTTPS"],
        "htss": result["HSTS"],
        "hsts_entire_domain": result["HSTS Entire Domain"],
        "hsts_header": result["HSTS Header"],
        "hsts_max_age": result["HSTS Max Age"],
        "hsts_preload_pending": result["HSTS Preload Pending"],
        "hsts_preload_ready": result["HSTS Preload Ready"],
        "hsts_preloaded": result["HSTS Preloaded"],
        "https_bad_chain": result["HTTPS Bad Chain"],
        "https_bad_hostname": result["HTTPS Bad Hostname"],
        "https_cert_chain_length": result["HTTPS Cert Chain Length"],
        "https_client_auth_required": result["HTTPS Client Auth Required"],
        "https_custom_truststore_trusted": result["HTTPS Custom Truststore Trusted"],
        "https_expired_cert": result["HTTPS Expired Cert"],
        "https_full_connection": result["HTTPS Full Connection"],
        "https_live": result["HTTPS Live"],
        "https_probably_missing_intermediate_cert": result[
            "HTTPS Probably Missing Intermediate Cert"
        ],
        "https_publicly_trusted": result["HTTPS Publicly Trusted"],
        "https_self_signed_cert": result["HTTPS Self Signed Cert"],
        "https_leaf_cert_expiration_date": result["HTTPS LEAF CERT EXPIRATION DATE"],
        "https_leaf_cert_issuer": result["HTTPS LEAF CERT ISSUER"],
        "https_leaf_cert_subject": result["HTTPS LEAF CERT SUBJECT"],
        "https_root_cert_issuer": result["HTTPS ROOT CERT ISSUER"],
        "ip": result["IP"],
        "live": result["Live"],
        "notes": result["Notes"],
        "redirect": result["Redirect"],
        "redirect_to": result["Redirect To"],
        "server_header": result["Server Header"],
        "server_version": result["Server Version"],
        "strictly_forces_https": result["Strictly Forces HTTPS"],
        "unknown_error": result["Unknown Error"],
        "valid_https": result["Valid HTTPS"],
        "ep_http_headers": json.dumps(result["endpoints"]["http"]["headers"]),
        "ep_http_server_header": result["endpoints"]["http"]["server_header"],
        "ep_http_server_version": result["endpoints"]["http"]["server_version"],
        "ep_https_headers": json.dumps(result["endpoints"]["https"]["headers"]),
        "ep_https_hsts_header": result["endpoints"]["https"]["hsts_header"],
        "ep_https_server_header": result["endpoints"]["https"]["server_header"],
        "ep_https_server_version": result["endpoints"]["https"]["server_version"],
        "ep_httpswww_headers": json.dumps(result["endpoints"]["httpswww"]["headers"]),
        "ep_httpswww_hsts_header": result["endpoints"]["httpswww"]["hsts_header"],
        "ep_httpswww_server_header": result["endpoints"]["httpswww"]["server_header"],
        "ep_httpswww_server_version": result["endpoints"]["httpswww"]["server_version"],
        "ep_httpwww_headers": json.dumps(result["endpoints"]["httpwww"]["headers"]),
        "ep_httpwww_server_header": result["endpoints"]["httpwww"]["server_header"],
        "ep_httpwww_server_version": result["endpoints"]["httpwww"]["server_version"],
        "date_scanned": str(datetime.datetime.now().date()),
        "organizations_uid": sub["organizations_uid"],
        "sub_domain_uid": sub["sub_domain_uid"],
        "sub_domain": sub["sub_domain"],
    }

    return result_dict


def run_pshtt(domains, thread):
    """Run pshtt."""
    if len(domains) > 0:

        for sub in domains:
            print(f"{thread}: running for {sub['sub_domain']}")
            utils.configure_logging(False)

            domains = utils.format_domains([sub["sub_domain"]])

            options = {
                "user_agent": None,
                "timeout": None,
                "cache-third-parties": None,
                "ca_file": None,
                "pt_int_ca_file": None,
            }

            # Do the domain inspections
            try:
                print(domains)
                results = inspect_domains(domains, options)

                for result in results:
                    print(result)
                    formatted_dict = format_pshtt_result(result, sub)
                    api_pshtt_insert(formatted_dict)

            except Exception as e:
                print(e)
                print(f"failed result {results}")


def launch_pe_pshtt():
    """Run main."""
    subs = api_pshtt_domains_to_run()

    subs_array = np.array_split(subs, 3)
    print(len(subs_array))
    # thread 1
    subs_chunk1 = list(subs_array[0])
    thread1 = "Thread 1:"
    t1 = threading.Thread(target=run_pshtt, args=(subs_chunk1, thread1))

    # thread 2
    subs_chunk2 = list(subs_array[1])
    thread2 = "Thread 2:"
    t2 = threading.Thread(target=run_pshtt, args=(subs_chunk2, thread2))

    # thread 3
    subs_chunk3 = list(subs_array[2])
    thread3 = "Thread 3:"
    t3 = threading.Thread(target=run_pshtt, args=(subs_chunk3, thread3))

    # thread 4
    # subs_chunk4 = list(subs_array[3])
    # thread4 = "Thread 4:"
    # t4 = threading.Thread(target=run_pshtt, args=(subs_chunk4, thread4))

    # thread 5
    # subs_chunk5 = list(subs_array[4])
    # thread5 = "Thread 5:"
    # t5 = threading.Thread(target=run_pshtt, args=(subs_chunk5, thread5))

    # start threads
    t1.start()
    t2.start()
    t3.start()
    # t4.start()
    # t5.start()

    t1.join()
    t2.join()
    t3.join()
    # t4.join()
    # t5.join()

    print("All threads have finished.")


def main():
    """Run PSHTT Scan on P&E orgs."""
    launch_pe_pshtt()


if __name__ == "__main__":
    main()
