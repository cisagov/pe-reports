"""Runs queries through Shodan and compare the results to the CIDRs found in the cyhy database."""
# Standard Python Libraries
import time

# Third-Party Libraries
import pandas as pd
from pe_db.run import close, connect
import shodan


def query_software():
    """Identify queries that have already been run and remove them from the list."""
    software_list = []
    conn = connect()
    df = pd.read_csv("log4j_hits/software_run.csv")
    list1 = df["software"].to_list()
    sql = """SELECT software_name FROM unique_software"""
    df = pd.read_sql_query(sql, conn)
    close(conn)
    for i, row in df.iterrows():
        software_list.append(row["software_name"])
    software_list = list(set(software_list) - set(list1))
    return software_list


def search(api, query):
    """Run the query through Shodan and extract the json."""
    data = []
    # Wrap the request in a try/ except block to catch errors
    try:
        # Search Shodan
        results = api.search(query)
        total = results["total"]
        # Show the results
        print("Results found: {}".format(total))
        for result in results["matches"]:
            data.append(result)

    except shodan.APIError as e:
        print("Error: {}".format(e))

    i = len(results["matches"])
    j = 2
    error_count = 0
    while i < total:
        print(f"Page {j}")
        try:
            time.sleep(0.5)
            # Search Shodan
            results = api.search(query, page=j)

            # Show the results
            print(len(results["matches"]))
            for result in results["matches"]:
                data.append(result)
            i = i + len(results["matches"])
            j = j + 1
            if len(results["matches"]) == 0:
                i = total
            error_count = 0

        except shodan.APIError as e:
            error_count += 1
            print("Error: {}".format(e))
            if error_count == 5:
                time.sleep(15)
            elif error_count == 15:
                time.sleep(15)
                j += 1
    print(data)
    return data
    # with open(output_file, 'w') as f:
    #     json.dump(data, f)


def process_file(input_data, sw):
    """Extract the relevant information from the json file."""
    # excluded_fields = [
    #     "<",
    #     "error",
    #     "body",
    #     "background",
    #     "z-index",
    #     "height",
    #     "display",
    #     "bottom",
    #     "width",
    #     "left",
    #     "font",
    #     "align",
    #     "margin",
    #     "position",
    #     "color",
    #     "overflow",
    #     "right",
    # ]
    data = []
    # i = 0
    # data_fields = []
    # temp_fields = set()

    for line in input_data:
        l_dict = dict()
        print(line)
        print(line["ssl"])
        try:
            l_dict["SSL Versions Supported"] = line["ssl"]["versions"]

        except KeyError:
            pass
        l_dict["Organization"] = line["org"]
        l_dict["IP"] = line["ip_str"]
        l_dict["Port"] = line["port"]
        l_dict["Time"] = line["timestamp"]
        l_dict["ISP"] = line["isp"]
        l_dict["Transport"] = line["transport"]
        l_dict["OS"] = line["os"]
        l_dict["affected_product"] = sw
        try:
            l_dict["Product"] = line["product"]
        except KeyError:
            pass
        l_dict["Domains"] = line["domains"]
        data.append(l_dict)

    df = pd.DataFrame(data)
    print(df.columns)

    return df


def query_ip(ip):
    """Run an IP against the cyhy_db_assets table for matching cidrs."""
    conn = connect("")
    sql = """SELECT * FROM cyhy_db_assets
    WHERE network >>= '%s'"""
    df = pd.read_sql_query(sql, conn, (ip))
    close(conn)
    return df


def process_ips(df, filename):
    """Retrieve cyhy information for matching ips."""
    list = []
    for i, row in df.iterrows():
        cyhy_df = query_ip(row["IP"])
        for j, asset in cyhy_df.iterrows():
            obj = {
                "org_id": asset["org_id"],
                "org_name": asset["org_name"],
                "contact": asset["contact"],
                "network": asset["network"],
                "type": asset["type"],
                "ip": row["IP"],
                "product": row["affected_product"],
            }
            list.append(obj)

    affected_assets = pd.DataFrame(list)
    if len(affected_assets) > 0:
        affected_assets.to_csv("log4j_hits/" + filename)
        affected_assets.to_csv(
            "log4j_hits/all_hits.csv", mode="a", index=False, header=False
        )
    else:
        print("no hits")
    time.sleep(5)
    return 0


def main():
    """Run queries through shodan and compare results to cyhy_assets db."""
    # get username and password from config file
    key = "<<SHODAN API KEY GOES HERE>>"
    api = shodan.Shodan(key)
    # software = query_software()
    queries = ["List of shodan quereis go here"]
    for query in queries:
        # try:
        print("running on " + query)
        if query in ["null", "", "Basic"]:
            continue
        query = f"{query} country:US"
        data = search(api, query)
        df = process_file(data, query)
        process_ips(df, query.replace(" ", "_") + ".csv")
        final = pd.DataFrame([{"software": query, "run_successfully": True}])
        final.to_csv("log4j_hits/software_run.csv", mode="a", index=False, header=False)
        # except:
        #     final = pd.DataFrame([{'software': sw, 'run_successfully':False}])
        #     final.to_csv("log4j_hits/software_run.csv", mode='a', index=False, header=False)
        #     continue


if __name__ == "__main__":
    main()
