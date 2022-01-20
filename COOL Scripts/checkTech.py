"""Run through all FCEB subdomains and identifies services running on those domains."""
# Standard Python Libraries
import logging
import re
import threading

# Third-Party Libraries
import numpy as np
import pandas as pd

# Import from local module 'config'
from pe_db.config import config, config2
import psycopg2
import psycopg2.extras
import sublist3r
import urllib3
from webtech import utils, webtech


def getSubdomain1(domain):
    """Enumerate subdomains for a given domain."""
    # allsubs = []
    subdomains = sublist3r.main(domain, 40, None, None, False, False, False, None)
    # subisolated = ''
    # for sub in subdomains:
    #     if sub != f'www.{domain}':
    #         print(sub)
    #         subisolated = sub.rsplit('.')[:-2]
    #         # subisolated = sub.rsplit('.',2)[:-2]
    #         print(f'The whole sub is {sub} and '
    #               f'the isolated sub is {subisolated}')
    #     allsubs.append(subisolated)
    return subdomains


def querySubs():
    """Query all the subdomains from the database."""
    params = config2()
    conn = psycopg2.connect(**params)
    """SQL 'SELECT' of a datafame"""
    sql = """select d."name" as domain, d.ip , d."fromRootDomain", d."subdomainSource"
        from organization o
        join organization_tag_organizations_organization otoo on o.id = otoo."organizationId"
        join organization_tag ot on ot.id = otoo."organizationTagId"
        join "domain" d on d."organizationId"  = o.id
        where ot."name" = 'FCEB';"""
    df = pd.read_sql_query(sql, conn)
    subs_list = df["domain"].to_list()
    conn.close()
    params = config()
    conn = psycopg2.connect(**params)
    sql = """SELECT sub_url from asset_headers"""
    df = pd.read_sql_query(sql, conn)
    run_subs_list = df["sub_url"].to_list()
    url_list = list(set(subs_list) - set(run_subs_list))

    return url_list


def get_subs():
    """Get subdomains from the csv."""
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
                "insert into unique_software(software_name) values ('%s');",
                (softwareName),
            )

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
    """Check a domain for web technologies being run."""
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


def setsubInfo(suburl, techlist, interestinglist):
    """Insert domain into the database."""
    # logging.info(f"Started setAllDomains {hostname}")

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
                "insert into asset_headers(sub_url, tech_detected, interesting_header) values ('%s',ARRAY [%s],ARRAY [%s]);",
                (suburl, techlist, interestinglist),
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
    """Take subdomains, run them through webTech and save results to database."""
    # subdomaininfo = getSubdomain1(domain)
    # subs = querySubs()

    if len(subs) > 0:
        for sub in subs:
            detectedTech = []
            interestingInfo = []
            print(f"{thread}: running for {sub}")
            check = checkdomain(sub)
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
            print(f"{thread}: The domain is {sub}")
            print(detectedTech)
            print(interestingInfo)
            detectedTech = detectedTech
            interestingInfo = interestingInfo

            setsubInfo(sub, detectedTech, interestingInfo)
            software = getAllSoftwareNames()
            for name in detectedTech:
                if name not in software:
                    setUniqueSoftware(name)


def main():
    """Query subdomains and run them through threads of webTech."""
    # df = pd.read_csv('current-federal-agency-list-only.csv')
    # checkAssetSoftware("")
    subs = get_subs()
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
    subs_chunk4 = list(subs_array[3])
    thread4 = "Thread 4:"
    t4 = threading.Thread(target=checkAssetSoftware, args=(subs_chunk4, thread4))

    # thread 4
    # subs_chunk5 = list(subs_array[4])
    # thread5 = "Thread 5:"
    # t5 = threading.Thread(target=checkAssetSoftware, args=(subs_chunk5, thread5))

    # start threads
    t1.start()
    t2.start()
    t3.start()
    t4.start()
    # t5.start()

    t1.join()
    t2.join()
    t3.join()
    t4.join()
    # t5.join()

    print("All threads have finished.")


if __name__ == "__main__":
    main()
