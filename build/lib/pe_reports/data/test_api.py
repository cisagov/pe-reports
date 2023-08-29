import requests
import logging
import time
import json
import pandas as pd
pe_api_key = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJleHAiOjE2OTA0OTIwNDksInN1YiI6ImNkdWhuNzUifQ.ESEuzmAdSD63LIzdSHC9v2HwPRKWv_hfJkFB4GGt1J8'#CONN_PARAMS_DIC_STAGING.get("pe_api_key")
pe_api_url = 'http://127.0.0.1:8000/apiv1/'#CONN_PARAMS_DIC_STAGING.get("pe_api_url")


LOGGER = logging.getLogger(__name__)


def api_darkweb_cves():
    """
    Query all the darkweb cves from top_cves table

    Return:
        List of all darkweb_cves
    """
    # Endpoint info
    create_task_url = pe_api_url + "darkweb_cves"
    check_task_url = pe_api_url + "darkweb_cves/task/"
    headers = {
        "Content-Type": "application/json",
        "access_token": pe_api_key,
    }
    task_status = "Pending"
    check_task_resp = ""
    data = json.dumps({"page": 2, "per_page": 250000})
    try:
        # Create task for query
        create_task_result = requests.post(create_task_url, headers=headers).json()
        task_id = create_task_result.get("task_id")
        LOGGER.info(
            "Created task for query cves endpoint query, task_id: ", task_id
        )
        # Once task has been started, keep pinging task status until finished
        check_task_url += task_id
        while task_status != "Completed" and task_status != "Failed":
            # Ping task status endpoint and get status
            check_task_resp = requests.get(check_task_url, headers=headers).json()
            task_status = check_task_resp.get("status")
            LOGGER.info(
                "\tPinged xl_stakeholders status endpoint, status:", task_status
            )
            time.sleep(3)
    except requests.exceptions.HTTPError as errh:
        LOGGER.error(errh)
    except requests.exceptions.ConnectionError as errc:
        LOGGER.error(errc)
    except requests.exceptions.Timeout as errt:
        LOGGER.error(errt)
    except requests.exceptions.RequestException as err:
        LOGGER.error(err)
    except json.decoder.JSONDecodeError as err:
        LOGGER.error(err)

    # Once task finishes, return result
    if task_status == "Completed":
        result_df = check_task_resp.get("result")
        return result_df
    else:
        raise Exception("Darkweb CVES query failed, details: ", check_task_resp)
    
def task_api_call(task_url, check_url, data={},retry_time=3):
    # Endpoint info
    create_task_url = pe_api_url + task_url
    check_task_url = pe_api_url + check_url
    headers = {
        "Content-Type": "application/json",
        "access_token": pe_api_key,
    }
    task_status = "Pending"
    check_task_resp = ""
    try:
        # Create task for query
        create_task_result = requests.post(create_task_url, headers=headers , data=data).json()
        task_id = create_task_result.get("task_id")
        LOGGER.info(
            "Created task for query, task_id: ", task_id
        )
        check_task_url += task_id
        while task_status != "Completed" and task_status != "Failed":
            # Ping task status endpoint and get status
            check_task_resp = requests.get(check_task_url, headers=headers).json()
            task_status = check_task_resp.get("status")
            LOGGER.info(
                "\tPinged xl_stakeholders status endpoint, status:", task_status
            )
            time.sleep(retry_time)
    except requests.exceptions.HTTPError as errh:
        LOGGER.error(errh)
    except requests.exceptions.ConnectionError as errc:
        LOGGER.error(errc)
    except requests.exceptions.Timeout as errt:
        LOGGER.error(errt)
    except requests.exceptions.RequestException as err:
        LOGGER.error(err)
    except json.decoder.JSONDecodeError as err:
        LOGGER.error(err)

    # Once task finishes, return result
    if task_status == "Completed":
        return check_task_resp.get("result")
    else:
        raise Exception("API calls failed ", check_task_resp)
    
#def api_call(task_url,data={}):
    
def query_darkweb_cves(table):
    """"""
    result = task_api_call("darkweb_cves","darkweb_cves/task/")
    result_df = pd.DataFrame.from_dict(result)
    result_df.rename(
            columns={
                "data_source_uid_id": "data_source_uid",
            },
            inplace=True,
    )
    result_df["date"] = pd.to_datetime(result_df["date"]).dt.date
    return result_df


def query_darkweb(org_uid, start_date, end_date, table):
    # Endpoint info
    endpoint_url = pe_api_url + "darkweb_data"
    headers = {
        "Content-Type": "application/json",
        "access_token": pe_api_key,
    }
    data = json.dumps({"table": table, "org_uid": org_uid, "start_date": start_date, "end_date": end_date})
    try:
        # Call endpoint
        result = requests.post(endpoint_url, headers=headers, data=data).json()
        # Process data and return
        result_df = pd.DataFrame.from_dict(result)
        result_df.rename(
            columns={
               "organizations_uid_id": "organizations_uid",
               "data_source_uid_id": "data_source_uid",
            },
            inplace=True,
        )
        result_df["date"] = pd.to_datetime(result_df["date"]).dt.date
        return result_df
    except requests.exceptions.HTTPError as errh:
        LOGGER.info(errh)
    except requests.exceptions.ConnectionError as errc:
        LOGGER.info(errc)
    except requests.exceptions.Timeout as errt:
        LOGGER.info(errt)
    except requests.exceptions.RequestException as err:
        LOGGER.info(err)
    except json.decoder.JSONDecodeError as err:
        LOGGER.info(err)

if __name__ == "__main__":
    print(query_darkweb("385cac70-416f-11ec-bf38-02589a36c9d7","2022-01-01","2022-03-26","mentions"))
    #print(api_darkweb_cves())
    