"""Check tech script."""
# Standard Python Libraries
import json
import logging
import re
import threading

# Third-Party Libraries
import numpy as np
import pandas as pd

# Import from local module 'config'
from pe_db.config import config
import psycopg2
import psycopg2.extras
from sslyze import (
    ScanCommandAttemptStatusEnum,
    Scanner,
    ServerNetworkLocation,
    ServerScanRequest,
    ServerScanStatusEnum,
)
from sslyze.scanner.scan_command_attempt import ScanCommandAttempt
import urllib3
from webtech import utils, webtech


def _print_failed_scan_command_attempt(
    scan_command_attempt: ScanCommandAttempt,
) -> None:
    """Print failures."""
    print(
        f"\nError when running ssl_2_0_cipher_suites: {scan_command_attempt.error_reason}:\n"
        f"{scan_command_attempt.error_trace}"
    )


def sslyze(sub):
    """Run sslyze."""
    try:
        all_scan_requests = [
            ServerScanRequest(
                server_location=ServerNetworkLocation(hostname=sub["sub_domain"])
            )
        ]
    except Exception:
        print("Error resolving the supplied hostnames")
        return [([], [], [])]
    list_of_tuples = []
    scanner = Scanner()
    scanner.queue_scans(all_scan_requests)
    print()
    result_list = list(scanner.get_results())

    for server_scan_result in result_list:
        print(f"\n\n****Results for {server_scan_result.server_location.hostname}****")

        # Were we able to connect to the server and run the scan?
        if server_scan_result.scan_status == ServerScanStatusEnum.ERROR_NO_CONNECTIVITY:
            # No we weren't
            print(
                f"\nError: Could not connect to {server_scan_result.server_location.hostname}:"
                f" {server_scan_result.connectivity_error_trace}"
            )
            continue

        # Since we were able to run the scan, scan_result is populated
        # assert server_scan_result.scan_result

        # Process the result of the SSL 2.0 scan command
        ssl2_attempt = server_scan_result.scan_result.ssl_2_0_cipher_suites
        ssl2_list = []
        if ssl2_attempt.status == ScanCommandAttemptStatusEnum.ERROR:
            # An error happened when this scan command was run
            _print_failed_scan_command_attempt(ssl2_attempt)
        elif ssl2_attempt.status == ScanCommandAttemptStatusEnum.COMPLETED:
            # This scan command was run successfully
            ssl2_result = ssl2_attempt.result
            if ssl2_result:
                print("\nAccepted cipher suites for SSL 2.0:")
                for accepted_cipher_suite in ssl2_result.accepted_cipher_suites:
                    ssl2_list.appen(accepted_cipher_suite.cipher_suite.name)

        # Process the result of the TLS 1.3 scan command
        tls1_3_attempt = server_scan_result.scan_result.tls_1_3_cipher_suites
        tls1_3_list = []
        if tls1_3_attempt.status == ScanCommandAttemptStatusEnum.ERROR:
            _print_failed_scan_command_attempt(ssl2_attempt)
        elif tls1_3_attempt.status == ScanCommandAttemptStatusEnum.COMPLETED:
            tls1_3_result = tls1_3_attempt.result
            if tls1_3_result:
                print("\nAccepted cipher suites for TLS 1.3:")
                for accepted_cipher_suite in tls1_3_result.accepted_cipher_suites:
                    tls1_3_list.append(accepted_cipher_suite.cipher_suite.name)

        # Process the result of the certificate info scan command
        certinfo_attempt = server_scan_result.scan_result.certificate_info
        certinfo_list = []
        if certinfo_attempt.status == ScanCommandAttemptStatusEnum.ERROR:
            _print_failed_scan_command_attempt(certinfo_attempt)
        elif certinfo_attempt.status == ScanCommandAttemptStatusEnum.COMPLETED:
            certinfo_result = certinfo_attempt.result
            if certinfo_result:
                print("\nLeaf certificates deployed:")
                for cert_deployment in certinfo_result.certificate_deployments:
                    leaf_cert = cert_deployment.received_certificate_chain[0]
                    certinfo_list.append(
                        {
                            leaf_cert.public_key().__class__.__name__: leaf_cert.subject.rfc4514_string(),
                            "Serial": leaf_cert.serial_number,
                        }
                    )
        tup = (ssl2_list, tls1_3_list, certinfo_list)
        list_of_tuples.append(tup)
    if len(list_of_tuples) == 0:
        list_of_tuples.append(([], [], []))
    return list_of_tuples


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
            UPDATE asset_headers
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
    sql = """select sd.sub_domain, o."name", o.organizations_uid
        from "sub_domains" sd
        join root_domains rd ON rd.root_domain_uid = sd.root_domain_uid
        join organizations o on o.organizations_uid = rd.organizations_uid;"""
    all_subs = pd.read_sql_query(sql, conn)

    sql = """
    SELECT ah.sub_url from asset_headers ah
    where ah.scanned != True
    """
    df = pd.read_sql_query(sql, conn)
    run_subs_list = list(set(df["sub_url"].to_list()))
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
                run_subs_list = list(set(df["sub_url"].to_list()))
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


def get_subs():
    """Get subs."""
    df = pd.read_csv("fceb_subdomains.csv")
    subs_list = df["domain"].to_list()
    params = config()
    conn = psycopg2.connect(**params)
    sql = """SELECT sub_url from asset_headers"""
    df = pd.read_sql_query(sql, conn)
    run_subs_list = df["sub_url"].to_list()
    url_list = list(set(subs_list) - set(run_subs_list))
    url_list.sort()

    return url_list


def setUniqueSoftware(softwareName):
    """Insert software name into the database."""
    # logging.info(f"Started setAllDomains {hostname}")
    try:
        logging.info("Got here in setSoftwareNames")

        params = config()

        conn = psycopg2.connect(**params)

        if conn:
            logging.info(
                "There was a connection made to the database and the query was executed "
            )

            cursor = conn.cursor()

            cursor.execute(
                "insert into unique_software(software_name) values ('{}');"
            ).format(softwareName)

    except (Exception, psycopg2.DatabaseError) as err:
        print("setuniquesoftware error")
        logging.error(f"There was a problem logging into the psycopg database {err}")
    finally:
        if conn:
            conn.commit()
            cursor.close()
            conn.close()
            logging.info("The connection/query was completed and closed.")


def getAllSoftwareNames():
    """Make database pull to get available domain name and IP address."""
    resultList = []
    try:
        # logging.info('Got here in getAll DomainInfo')

        params = config()

        conn = psycopg2.connect(**params)

        if conn:
            logging.info(
                "There was a connection made to the database and the query was executed "
            )

            cursor = conn.cursor(cursor_factory=psycopg2.extras.DictCursor)

            cursor.execute("select software_name from unique_software;")

            result = cursor.fetchall()

            for row in result:
                theSoftware = row[0]

                resultList.append(theSoftware)
            return resultList

    except (Exception, psycopg2.DatabaseError) as err:
        print("getallsoftware error")
        logging.error(f"There was a problem logging into the psycopg database {err}")
    finally:
        if conn:
            cursor.close()
            conn.close()
            logging.info("The connection/query was completed and closed.")

            return resultList


def checkdomain(domainasset):
    """Check domain."""
    wt = webtech.WebTech()
    try:

        results = wt.start_from_url(f"https://{domainasset}", timeout=3)
        if results:
            return results
    except urllib3.exceptions.MaxRetryError as err:
        print(f"There is a timeout error {err}")
    except utils.ConnectionException as webtecherr:
        print(f"There was a webtech error {webtecherr}")
    except AttributeError as atterr:
        print(f"There was a attribute error {atterr}")


def setsubInfo(suburl, techlist, interestinglist, ssl_info):
    """Insert domain into the database."""
    # logging.info(f"Started setAllDomains {hostname}")
    ssl2_list = ssl_info[0]
    tls1_3_list = ssl_info[1]
    certinfo_list = json.dumps(ssl_info[2])
    try:
        logging.info("Got here in setAllDomains")

        params = config()

        conn = psycopg2.connect(**params)

        if conn:

            logging.info(
                "There was a connection made to the database and the query was executed "
            )

            cursor = conn.cursor()

            cursor.execute(
                """
                INSERT INTO asset_headers(organizations_uid, sub_url, tech_detected, interesting_header, ssl2, tls1, certificate, scanned)
                VALUES (%s, %s, ARRAY [%s], ARRAY [%s], %s, %s, %s, %s)
                ON CONFLICT (organizations_uid, sub_url)
                DO
                UPDATE SET tech_detected = EXCLUDED.tech_detected, interesting_header = EXCLUDED.interesting_header, ssl2 = EXCLUDED.ssl2, tls1 = EXCLUDED.tls1, certificate = EXCLUDED.certificate, scanned = TRUE;
                """,
                (
                    suburl["organizations_uid"],
                    suburl["sub_domain"],
                    techlist,
                    interestinglist,
                    ssl2_list,
                    tls1_3_list,
                    certinfo_list,
                    "1",
                ),
            )

    except (Exception, psycopg2.DatabaseError) as err:
        print("setsubinfo error")
        logging.error(f"There was a problem logging into the psycopg database {err}")
    finally:
        if conn:
            conn.commit()
            cursor.close()
            conn.close()
            logging.info("The connection/query was completed and closed.")


def checkAssetSoftware(subs, thread):
    """Check asset software."""
    if len(subs) > 0:
        for sub in subs:
            if sub["sub_domain"] == "Null_Sub":
                continue
            detectedTech = []
            interestingInfo = []
            print(f"{thread}: running for {sub['sub_domain']}")
            check = checkdomain(sub["sub_domain"])
            if check:
                theassetInfo = check.split("\n")
                techCount = 0
                interestingCount = 0
                serverCount = 0
                for data in theassetInfo:
                    # print(f'The data is {data}')
                    # print(f'the count is {techCount}')
                    if "Detected technologies" in data:
                        techCount += 1
                    elif (
                        techCount == 1
                        and interestingCount == 0
                        and "Detected technologies" not in data
                        and "interesting custom" not in data
                    ):
                        data = re.sub(r"[-\n\t]*", "", data)
                        detectedTech.append(data)
                    elif "interesting custom" in data:
                        interestingCount += 1
                    elif (
                        "Server:" in data and interestingCount == 1 and serverCount <= 1
                    ):
                        serverCount += 1
                        data = data.split(":", 1)[1]
                        interestingInfo.append(data)

                    else:
                        pass
            if not detectedTech:
                detectedTech.append("NULL")
            if not interestingInfo:
                interestingInfo.append("NULL")
            print(f"{thread}: The domain is {sub['sub_domain']}")
            print(detectedTech)
            print(interestingInfo)
            ssl_info = sslyze(sub)
            if len(ssl_info) > 1:
                print(f"There are {len(ssl_info)} different ssl results")
                quit()
            setsubInfo(sub, detectedTech, interestingInfo, ssl_info[0])
            software = getAllSoftwareNames()
            for name in detectedTech:
                if name not in software:
                    setUniqueSoftware(name)


def main():
    """Run main."""
    subs = querySubs()
    subs_array = np.array_split(subs, 4)

    # thread 1
    subs_chunk1 = list(subs_array[0])
    thread1 = "Thread 1:"
    t1 = threading.Thread(target=checkAssetSoftware, args=(subs_chunk1, thread1))

    # thread 2
    subs_chunk2 = list(subs_array[1])
    thread2 = "Thread 2:"
    t2 = threading.Thread(target=checkAssetSoftware, args=(subs_chunk2, thread2))

    # thread 3
    subs_chunk3 = list(subs_array[2])
    thread3 = "Thread 3:"
    t3 = threading.Thread(target=checkAssetSoftware, args=(subs_chunk3, thread3))

    # thread 4
    # subs_chunk4 = list(subs_array[3])
    # thread4 = "Thread 4:"
    # t4 = threading.Thread(target=checkAssetSoftware, args=(subs_chunk4, thread4))

    # thread 5
    # subs_chunk5 = list(subs_array[4])
    # thread5 = "Thread 5:"
    # t5 = threading.Thread(target=checkAssetSoftware, args=(subs_chunk5, thread5))

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
