"""Pshtt wrapper."""
# Standard Python Libraries
import json
import logging
import threading

# Third-Party Libraries
# from pshtt.pshtt.utils import smart_open
from data.config import config
from data.run import getDataSource
import numpy as np
import pandas as pd
import pshtt.pshtt
from pshtt.pshtt import utils
import psycopg2
from psycopg2.extensions import AsIs


def reset_scanned():
    """Reset scanned."""
    conn = None
    updated_rows = 0
    try:
        params = config()
        conn = psycopg2.connect(**params)
        cur = conn.cursor()

        cur.execute(
            """
            UPDATE pshtt_results
            SET scanned = FALSE;
            """
        )

        updated_rows = cur.rowcount
    except (Exception, psycopg2.DatabaseError) as error:
        print(error)
    finally:
        if conn is not None:
            conn.close()

    return updated_rows


def querySubs():
    """Query subs."""
    params = config()
    conn = psycopg2.connect(**params)
    """SQL 'SELECT' of a datafame"""
    sql = """select sd.sub_domain_uid, sd.sub_domain, o."name", o.organizations_uid
        from "sub_domains" sd
        join root_domains rd ON rd.root_domain_uid = sd.root_domain_uid
        join organizations o on o.organizations_uid = rd.organizations_uid;"""

    all_subs = pd.read_sql_query(sql, conn)

    sql = """
    SELECT pr.sub_domain from pshtt_results pr
    where pr.scanned is True;
    """
    df = pd.read_sql_query(sql, conn)
    run_subs_list = list(set(df["sub_domain"].to_list()))
    cleaned = all_subs[~all_subs["sub_domain"].isin(run_subs_list)]
    if len(cleaned) == 0:
        while True:
            txt = input(
                "All subdomains have been scanned. Would you like to reset all subdomains to unscanned and continue? (Y/N)"
            )
            if txt == "Y":
                num_rows_reset = reset_scanned()
                if num_rows_reset > 0:
                    df = pd.read_sql_query(sql, conn)
                run_subs_list = list(set(df["sub_domain"].to_list()))
                cleaned = all_subs[~all_subs["sub_domain"].isin(run_subs_list)]
                break
            elif txt == "N":
                quit()
            else:
                print("Invalid input. Enter either Y or N")
                continue

    conn.close
    list_of_dicts = cleaned.to_dict("records")

    return list_of_dicts


def saveResults(results, sub):
    """Insert domain into the database."""
    # logging.info(f"Started setAllDomains {hostname}")
    print("Saving result")
    for result in list(results):
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
            "https_custom_truststore_trusted": result[
                "HTTPS Custom Truststore Trusted"
            ],
            "https_expired_cert": result["HTTPS Expired Cert"],
            "https_full_connection": result["HTTPS Full Connection"],
            "https_live": result["HTTPS Live"],
            "https_probably_missing_intermediate_cert": result[
                "HTTPS Probably Missing Intermediate Cert"
            ],
            "https_publicly_trusted": result["HTTPS Publicly Trusted"],
            "https_self_signed_cert": result["HTTPS Self Signed Cert"],
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
            "ep_http_ip": result["endpoints"]["http"]["ip"],
            "ep_http_live": result["endpoints"]["http"]["live"],
            "ep_http_notes": result["endpoints"]["http"]["notes"],
            "ep_http_redirect": result["endpoints"]["http"]["redirect"],
            "ep_http_redirect_eventually_to": result["endpoints"]["http"][
                "redirect_eventually_to"
            ],
            "ep_http_redirect_eventually_to_external": result["endpoints"]["http"][
                "redirect_eventually_to_external"
            ],
            "ep_http_redirect_eventually_to_http": result["endpoints"]["http"][
                "redirect_eventually_to_http"
            ],
            "ep_http_redirect_eventually_to_https": result["endpoints"]["http"][
                "redirect_eventually_to_https"
            ],
            "ep_http_redirect_eventually_to_subdomain": result["endpoints"]["http"][
                "redirect_eventually_to_subdomain"
            ],
            "ep_http_redirect_immediately_to": result["endpoints"]["http"][
                "redirect_immediately_to"
            ],
            "ep_http_redirect_immediately_to_external": result["endpoints"]["http"][
                "redirect_immediately_to_external"
            ],
            "ep_http_redirect_immediately_to_http": result["endpoints"]["http"][
                "redirect_immediately_to_http"
            ],
            "ep_http_redirect_immediately_to_https": result["endpoints"]["http"][
                "redirect_immediately_to_https"
            ],
            "ep_http_redirect_immediately_to_subdomain": result["endpoints"]["http"][
                "redirect_immediately_to_subdomain"
            ],
            "ep_http_redirect_immediately_to_www": result["endpoints"]["http"][
                "redirect_immediately_to_www"
            ],
            "ep_http_server_header": result["endpoints"]["http"]["server_header"],
            "ep_http_server_version": result["endpoints"]["http"]["server_version"],
            "ep_http_status": result["endpoints"]["http"]["status"],
            "ep_http_unknown_error": result["endpoints"]["http"]["unknown_error"],
            "ep_http_url": result["endpoints"]["http"]["url"],
            "ep_https_headers": json.dumps(result["endpoints"]["https"]["headers"]),
            "ep_https_hsts": result["endpoints"]["https"]["hsts"],
            "ep_https_hsts_all_subdomains": result["endpoints"]["https"][
                "hsts_all_subdomains"
            ],
            "ep_https_hsts_header": result["endpoints"]["https"]["hsts_header"],
            "ep_https_hsts_max_age": result["endpoints"]["https"]["hsts_max_age"],
            "ep_https_hsts_preload": result["endpoints"]["https"]["hsts_preload"],
            "ep_https_https_bad_chain": result["endpoints"]["https"]["https_bad_chain"],
            "ep_https_https_bad_hostname": result["endpoints"]["https"][
                "https_bad_hostname"
            ],
            "ep_https_https_cert_chain_len": result["endpoints"]["https"][
                "https_cert_chain_len"
            ],
            "ep_https_https_client_auth_required": result["endpoints"]["https"][
                "https_client_auth_required"
            ],
            "ep_https_https_custom_trusted": result["endpoints"]["https"][
                "https_custom_trusted"
            ],
            "ep_https_https_expired_cert": result["endpoints"]["https"][
                "https_expired_cert"
            ],
            "ep_https_https_vull_connection": result["endpoints"]["https"][
                "https_full_connection"
            ],
            "ep_https_https_missing_intermediate_cert": result["endpoints"]["https"][
                "https_missing_intermediate_cert"
            ],
            "ep_https_https_public_trusted": result["endpoints"]["https"][
                "https_public_trusted"
            ],
            "ep_https_https_self_signed_cert": result["endpoints"]["https"][
                "https_self_signed_cert"
            ],
            "ep_https_https_valid": result["endpoints"]["https"]["https_valid"],
            "ep_https_ip": result["endpoints"]["https"]["ip"],
            "ep_https_live": result["endpoints"]["https"]["live"],
            "ep_https_notes": result["endpoints"]["https"]["notes"],
            "ep_https_redirect": result["endpoints"]["https"]["redirect"],
            "ep_https_redireect_eventually_to": result["endpoints"]["https"][
                "redirect_eventually_to"
            ],
            "ep_https_redirect_eventually_to_external": result["endpoints"]["https"][
                "redirect_eventually_to_external"
            ],
            "ep_https_redirect_eventually_to_http": result["endpoints"]["https"][
                "redirect_eventually_to_http"
            ],
            "ep_https_redirect_eventually_to_https": result["endpoints"]["https"][
                "redirect_eventually_to_https"
            ],
            "ep_https_redirect_eventually_to_subdomain": result["endpoints"]["https"][
                "redirect_eventually_to_subdomain"
            ],
            "ep_https_redirect_immediately_to": result["endpoints"]["https"][
                "redirect_immediately_to"
            ],
            "ep_https_redirect_immediately_to_external": result["endpoints"]["https"][
                "redirect_immediately_to_external"
            ],
            "ep_https_redirect_immediately_to_http": result["endpoints"]["https"][
                "redirect_immediately_to_http"
            ],
            "ep_https_redirect_immediately_to_https": result["endpoints"]["https"][
                "redirect_immediately_to_https"
            ],
            "ep_https_redirect_immediately_to_subdomain": result["endpoints"]["https"][
                "redirect_immediately_to_subdomain"
            ],
            "ep_https_redirect_immediately_to_www": result["endpoints"]["https"][
                "redirect_immediately_to_www"
            ],
            "ep_https_server_header": result["endpoints"]["https"]["server_header"],
            "ep_https_server_version": result["endpoints"]["https"]["server_version"],
            "ep_https_status": result["endpoints"]["https"]["status"],
            "ep_https_unknown_error": result["endpoints"]["https"]["unknown_error"],
            "ep_https_url": result["endpoints"]["https"]["url"],
            "ep_httpswww_headers": json.dumps(
                result["endpoints"]["httpswww"]["headers"]
            ),
            "ep_httpswww_hsts": result["endpoints"]["httpswww"]["hsts"],
            "ep_httpswww_hsts_all_subdomains": result["endpoints"]["httpswww"][
                "hsts_all_subdomains"
            ],
            "ep_httpswww_hsts_header": result["endpoints"]["httpswww"]["hsts_header"],
            "ep_httpswww_hsts_max_age": result["endpoints"]["httpswww"]["hsts_max_age"],
            "ep_httpswww_hsts_preload": result["endpoints"]["httpswww"]["hsts_preload"],
            "ep_httpswww_https_bad_chain": result["endpoints"]["httpswww"][
                "https_bad_chain"
            ],
            "ep_httpswww_https_bad_hostname": result["endpoints"]["httpswww"][
                "https_bad_hostname"
            ],
            "ep_httpswww_https_cert_chain_len": result["endpoints"]["httpswww"][
                "https_cert_chain_len"
            ],
            "ep_httpswww_https_client_auth_required": result["endpoints"]["httpswww"][
                "https_client_auth_required"
            ],
            "ep_httpswww_https_custom_trusted": result["endpoints"]["httpswww"][
                "https_custom_trusted"
            ],
            "ep_httpswww_https_expired_cert": result["endpoints"]["httpswww"][
                "https_expired_cert"
            ],
            "ep_httpswww_https_full_connection": result["endpoints"]["httpswww"][
                "https_full_connection"
            ],
            "ep_httpswww_https_missing_intermediate_cert": result["endpoints"][
                "httpswww"
            ]["https_missing_intermediate_cert"],
            "ep_httpswww_https_public_trusted": result["endpoints"]["httpswww"][
                "https_public_trusted"
            ],
            "ep_httpswww_https_self_signed_cert": result["endpoints"]["httpswww"][
                "https_self_signed_cert"
            ],
            "ep_httpswww_https_valid": result["endpoints"]["httpswww"]["https_valid"],
            "ep_httpswww_ip": result["endpoints"]["httpswww"]["ip"],
            "ep_httpswww_live": result["endpoints"]["httpswww"]["live"],
            "ep_httpswww_notes": result["endpoints"]["httpswww"]["notes"],
            "ep_httpswww_redirect": result["endpoints"]["httpswww"]["redirect"],
            "ep_httpswww_redirect_eventually_to": result["endpoints"]["httpswww"][
                "redirect_eventually_to"
            ],
            "ep_httpswww_redirect_eventually_to_external": result["endpoints"][
                "httpswww"
            ]["redirect_eventually_to_external"],
            "ep_httpswww_redirect_eventually_to_http": result["endpoints"]["httpswww"][
                "redirect_eventually_to_http"
            ],
            "ep_httpswww_redirect_eventually_to_https": result["endpoints"]["httpswww"][
                "redirect_eventually_to_https"
            ],
            "ep_httpswww_redirect_eventually_to_subdomain": result["endpoints"][
                "httpswww"
            ]["redirect_eventually_to_subdomain"],
            "ep_httpswww_redirect_immediately_to": result["endpoints"]["httpswww"][
                "redirect_immediately_to"
            ],
            "ep_httpswww_redirect_immediately_to_external": result["endpoints"][
                "httpswww"
            ]["redirect_immediately_to_external"],
            "ep_httpswww_redirect_immediately_to_http": result["endpoints"]["httpswww"][
                "redirect_immediately_to_http"
            ],
            "ep_httpswww_redirect_immediately_to_https": result["endpoints"][
                "httpswww"
            ]["redirect_immediately_to_https"],
            "ep_httpswww_redirect_immediately_to_subdomain": result["endpoints"][
                "httpswww"
            ]["redirect_immediately_to_subdomain"],
            "ep_httpswww_redirect_immediately_to_www": result["endpoints"]["httpswww"][
                "redirect_immediately_to_www"
            ],
            "ep_httpswww_server_header": result["endpoints"]["httpswww"][
                "server_header"
            ],
            "ep_httpswww_server_version": result["endpoints"]["httpswww"][
                "server_version"
            ],
            "ep_httpswww_status": result["endpoints"]["httpswww"]["status"],
            "ep_httpswww_unknown_error": result["endpoints"]["httpswww"][
                "unknown_error"
            ],
            "ep_httpswww_url": result["endpoints"]["httpswww"]["url"],
            "ep_httpwww_headers": json.dumps(result["endpoints"]["httpwww"]["headers"]),
            "ep_httpwww_ip": result["endpoints"]["httpwww"]["ip"],
            "ep_httpwww_live": result["endpoints"]["httpwww"]["live"],
            "ep_httpwww_notes": result["endpoints"]["httpwww"]["notes"],
            "ep_httpwww_redirect": result["endpoints"]["httpwww"]["redirect"],
            "ep_httpwww_redirect_eventually_to": result["endpoints"]["httpwww"][
                "redirect_eventually_to"
            ],
            "ep_httpwww_redirect_eventually_to_external": result["endpoints"][
                "httpwww"
            ]["redirect_eventually_to_external"],
            "ep_httpwww_redirect_eventually_to_http": result["endpoints"]["httpwww"][
                "redirect_eventually_to_http"
            ],
            "ep_httpwww_redirect_eventually_to_https": result["endpoints"]["httpwww"][
                "redirect_eventually_to_https"
            ],
            "ep_httpwww_redirect_eventually_to_subdomain": result["endpoints"][
                "httpwww"
            ]["redirect_eventually_to_subdomain"],
            "ep_httpwww_redirect_immediately_to": result["endpoints"]["httpwww"][
                "redirect_immediately_to"
            ],
            "ep_httpwww_redirect_immediately_to_external": result["endpoints"][
                "httpwww"
            ]["redirect_immediately_to_external"],
            "ep_httpwww_redirect_immediately_to_http": result["endpoints"]["httpwww"][
                "redirect_immediately_to_http"
            ],
            "ep_httpwww_redirect_immediately_to_https": result["endpoints"]["httpwww"][
                "redirect_immediately_to_https"
            ],
            "ep_httpwww_redirect_immediately_to_subdomain": result["endpoints"][
                "httpwww"
            ]["redirect_immediately_to_subdomain"],
            "ep_httpwww_redirect_immediately_to_www": result["endpoints"]["httpwww"][
                "redirect_immediately_to_www"
            ],
            "ep_httpwww_server_header": result["endpoints"]["httpwww"]["server_header"],
            "ep_httpwww_server_version": result["endpoints"]["httpwww"][
                "server_version"
            ],
            "ep_httpwww_status": result["endpoints"]["httpwww"]["status"],
            "ep_httpwww_unknown_error": result["endpoints"]["httpwww"]["unknown_error"],
            "ep_httpwww_url": result["endpoints"]["httpwww"]["url"],
        }
        update = ""
        for col in result_dict.keys():
            update = update + col + " = EXCLUDED." + col + ", "
        update = update + " scanned = True;"

        result_dict["scanned"] = True
        result_dict["organizations_uid"] = sub["organizations_uid"]
        result_dict["sub_domain_uid"] = sub["sub_domain_uid"]
        result_dict["data_source_uid"] = getDataSource("Pshtt")[0]
        result_dict["sub_domain"] = sub["sub_domain"]

    try:
        logging.info("Got here in setAllDomains")

        params = config()

        conn = psycopg2.connect(**params)

        if conn:

            logging.info(
                "There was a connection made to the database and the query was executed "
            )

            cursor = conn.cursor()

            columns = result_dict.keys()
            values = [result_dict[column] for column in columns]

            insert_statement = """insert into pshtt_results (%s)
            values %s
            ON CONFLICT (organizations_uid, sub_domain_uid)
            DO
            UPDATE SET {}"""

            cursor.execute(
                insert_statement.format(update),
                (AsIs(",".join(columns)), tuple(values)),
            )
            print("saved successfully")
    except (Exception, psycopg2.DatabaseError) as err:
        print("setsubinfo error")
        logging.error(f"There was a problem logging into the psycopg database {err}")
    finally:
        if conn:
            conn.commit()
            cursor.close()
            conn.close()
            logging.info("The connection/query was completed and closed.")
        return


def run_pshtt(domains, thread):
    """Run pshtt."""
    if len(domains) > 0:

        for sub in domains:
            print(f"{thread}: running for {sub['sub_domain']}")
            # args = docopt.docopt(__doc__, version=__version__)
            utils.configure_logging(False)
            # out_filename = args['--output']

            # Read from a .csv, or allow domains on the command line.
            # domains = []
            # if args['INPUT'][0].endswith(".csv"):
            #     domains = utils.load_domains(args['INPUT'][0])
            # else:
            #     domains = args['INPUT']
            print(sub)
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
                results = pshtt.pshtt.inspect_domains(domains, options)
                print(f"Here are the results {results}")
                saveResults(results, sub)
            except Exception:
                print(f"failed result {results}")


def main():
    """Run main."""
    subs = querySubs()
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


if __name__ == "__main__":
    main()
