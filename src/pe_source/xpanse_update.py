"""Scan to track Xpanse alerts and incidents in the P&E database.

Usage:
  xpanse XPANSE_ORG_CSV_PATH [--orgs=ORG_LIST] [--last_modified=MOD_TIME] [--log-level=LEVEL]

Options:
  -h --help                         Show this message.
  XPANSE_ORG_CSV_PATH               The path to the XPANSE Business_unit CSV.
  -o --orgs=ORG_LIST                A semicolon-separated list of Xpanse business_units.
                                    If not specified, data will be gathered for all business_units.
                                    Orgs in the list must match the names in Xpanse. E.g. Culberson County, Texas; DHS - Citizenship and Immigration Services (CIS) - CISA
                                    [default: all]
  -m --last_modified=MOD_TIME       An integer in timestamp epoch milliseconds.
                                    Scan will pull all alerts and assets updated since the provided time.
                                    If not specified, data will be gathered for all assets and alerts. E.g. 1696996800000
                                    [default: all_time]
  -l --log-level=LEVEL              If specified, then the log level will be set to
                                    the specified value.  Valid values are "debug", "info",
                                    "warning", "error", and "critical". [default: info]
"""

# Standard Python Libraries
import csv
import datetime
import json
import logging
import sys
from typing import Any, Dict

# Third-Party Libraries
from _version import __version__
from data.pe_db.db_query_source import (  # api_pull_xpanse_vulns,
    api_xpanse_alert_insert,
    insert_or_update_business_unit,
)
import docopt
import pytz
import requests
from schema import And, Or, Schema, SchemaError, Use

# cisagov Libraries
import pe_reports
from pe_reports.data.config import staging_config

API_DIC = staging_config(section="xpanse")
xpanse_url = "https://api-cisa.crtx.federal.paloaltonetworks.com/public_api/"
api_key = API_DIC.get("api_key")
auth_id = API_DIC.get("auth_id")

LOGGER = logging.getLogger(__name__)


def pull_asset_data(xpanse_asset_id_list=[]):
    """Pull asset data from the Xpanse API."""
    assets = []

    url = xpanse_url + "v1/assets/get_asset_internet_exposure"
    request_data = {"asm_id_list": xpanse_asset_id_list}

    payload = json.dumps({"request_data": request_data})

    headers = {
        "x-xdr-auth-id": auth_id,
        "Authorization": api_key,
        "Content-Type": "application/json",
    }

    response = requests.request("POST", url, headers=headers, data=payload)

    resp_dict = response.json()

    for asset in resp_dict["reply"]["details"]:
        asset_dict = format_asset(asset)
        assets.append(asset_dict)

    return assets
    #   save_asset(asset_dict)


def pull_alerts_data(org_dict, business_units_list=[]):
    """Pull alerts data from the Xpanse API."""
    url = xpanse_url + "v2/alerts/get_alerts_multi_events"

    if len(business_units_list) == 0:
        business_units_list = list(org_dict.keys())

    for org in business_units_list:
        request_data = {"use_page_token": True}
        filters = []
        print(org)
        LOGGER.info("Running Xpanse alert pull on %s", org)
        filters.append(
            {"field": "business_units_list", "operator": "in", "value": [org]}
        )

        # TODO maybe change this to be creation time
        # if last_modified != "all_time":
        #     filters.append({
        #         "field": ""
        #     })

        if len(filters) > 0:
            request_data["filters"] = filters

        payload = json.dumps({"request_data": request_data})

        headers = {
            "x-xdr-auth-id": auth_id,
            "Authorization": api_key,
            "Content-Type": "application/json",
        }
        try:
            response = requests.request("POST", url, headers=headers, data=payload)

            resp_dict = response.json()

            page_token = resp_dict["reply"]["next_page_token"]
            LOGGER.info(
                "The current org has %s alerts", resp_dict["reply"]["total_count"]
            )

            for alert in resp_dict["reply"]["alerts"]:
                formatted_alert = format_alerts(alert, org_dict)
                # print(formatted_alert)

                api_xpanse_alert_insert(formatted_alert)
                # quit()
                # save_asset()

            while page_token is not None:
                request_data = {"next_page_token": page_token}

                payload = json.dumps({"request_data": request_data})

                response = requests.request("POST", url, headers=headers, data=payload)
                resp_dict = response.json()

                page_token = resp_dict["reply"]["next_page_token"]

                for alert in resp_dict["reply"]["alerts"]:
                    formatted_alert = format_alerts(alert, org_dict)
                    api_xpanse_alert_insert(formatted_alert)

        except Exception as e:
            LOGGER.error("Error querying assets for %s: %s.", org, e)


def format_asset(asset):
    """Format Xpanse asset to match db tables."""
    asset_dict = {
        "asm_id": asset.get("asm_ids", None),
        "asset_name": asset.get("name", None),
        "asset_type": asset.get("type", None),
        "last_observed": asset.get("last_observed", None),
        "first_observed": asset.get("first_observed", None),
        "externally_detected_providers": asset.get(
            "externally_detected_providers", None
        ),
        "created": asset.get("created", None),
        "ips": asset.get("ips", None),
        "active_external_services_types": asset.get(
            "active_external_services_types", None
        ),
        "domain": asset.get("domain", None),
        "certificate_issuer": asset.get("certificate_issuer", None),
        "certificate_algorithm": asset.get("certificate_algorithm", None),
        "certificate_classifications": asset.get("certificate_classifications", None),
        "resolves": asset.get("resolves", None),
        "top_level_asset_mapper_domain": asset["details"].get(
            "topLevelAssetMapperDomain", None
        ),
        "domain_asset_type": asset["details"].get("domainAssetType", None),
        "is_paid_level_domain": asset["details"].get("isPaidLevelDomain", None),
        "domain_details": asset["details"].get("domainDetails", None),
        "dns_zone": asset.get("dnsZone", None),
        "latest_sampled_ip": asset.get("latestSampledIp", None),
        "recent_ips": asset.get("recentIps", None),
        "external_services": asset.get("external_services", None),
        "externally_inferred_vulnerability_score": asset.get(
            "externally_inferred_vulnerability_score", None
        ),
        "externally_inferred_cves": asset.get("externally_inferred_cves", None),
        "explainers": asset.get("explainers", None),
        "tags": asset.get("tags", None),
    }

    return asset_dict


def format_alerts(alert, org_dict):
    """Format Xpanse alert to match db tables."""
    tags = (alert.get("tags", None),)
    business_units_list = []

    for tag in tags[0]:
        if tag.startswith("BU:"):
            business_units_list.append(tag[3:].strip())

    max_n = 20
    assets = []
    asset_ids = alert["asset_ids"]
    if asset_ids is not None:
        asset_id_chunks = [
            asset_ids[i : i + max_n] for i in range(0, len(asset_ids), max_n)
        ]

        for asset_chunk in asset_id_chunks:
            asset_response = pull_asset_data(asset_chunk)
            assets += asset_response

    services = []
    service_ids = alert["service_ids"]

    if service_ids is not None:
        service_id_chunks = [
            service_ids[i : i + max_n] for i in range(0, len(service_ids), max_n)
        ]

        for service_chunk in service_id_chunks:
            service_response = pull_service_data(service_chunk)

            if service_response is None:
                continue

            for service_obj in service_response:
                cves = []
                if service_obj["details"].get("inferredCvesObserved", None) is not None:
                    for cve in service_obj["details"].get("inferredCvesObserved", None):
                        cves.append(
                            (
                                {
                                    "cve_id": cve["inferredCve"]["cveId"],
                                    "cvss_score_v2": cve["inferredCve"].get(
                                        "cvssScoreV2", None
                                    ),
                                    "cve_severity_v2": cve["inferredCve"].get(
                                        "cveSeverityV2", None
                                    ),
                                    "cvss_score_v3": cve["inferredCve"].get(
                                        "cvssScoreV3", None
                                    ),
                                    "cve_severity_v3": cve["inferredCve"].get(
                                        "cveSeverityV3", None
                                    ),
                                },
                                {
                                    "inferred_cve_match_type": cve["inferredCve"][
                                        "inferredCveMatchMetadata"
                                    ].get("inferredCveMatchType", None),
                                    "product": cve["inferredCve"][
                                        "inferredCveMatchMetadata"
                                    ].get("product", None),
                                    "confidence": cve["inferredCve"][
                                        "inferredCveMatchMetadata"
                                    ].get("confidence", None),
                                    "vendor": cve["inferredCve"][
                                        "inferredCveMatchMetadata"
                                    ].get("vendor", None),
                                    "version_number": cve["inferredCve"][
                                        "inferredCveMatchMetadata"
                                    ].get("version", None),
                                    "activity_status": cve.get("activityStatus", None),
                                    "first_observed": cve.get("firstObserved", None),
                                    "last_observed": cve.get("lastObserved", None),
                                },
                            )
                        )

                services.append(
                    {
                        "service_id": service_obj.get("service_id", None),
                        "service_name": service_obj.get("service_name", None),
                        "service_type": service_obj.get("service_type", None),
                        "ip_address": service_obj.get(
                            "ip_address", None
                        ),  # list of ip strings
                        "domain": service_obj.get("domain", None),  # list of ?
                        "externally_detected_providers": service_obj.get(
                            "externally_detected_providers", None
                        ),
                        "is_active": service_obj.get("is_active", None),
                        "first_observed": service_obj.get("first_observed", None),
                        "last_observed": service_obj.get("last_observed", None),
                        "port": service_obj.get("port", None),
                        "protocol": service_obj.get("protocol", None),
                        "active_classifications": service_obj.get(
                            "active_classifications", None
                        ),  # list of strings
                        "inactive_classifications": service_obj.get(
                            "inactive_classifications", None
                        ),
                        "discovery_type": service_obj.get("discovery_type", None),
                        "externally_inferred_vulnerability_score": service_obj.get(
                            "externally_inferred_vulnerability_score", None
                        ),
                        "externally_inferred_cves": service_obj.get(
                            "externally_inferred_cves", None
                        ),
                        "service_key": service_obj["details"].get("serviceKey", None),
                        "service_key_type": service_obj["details"].get(
                            "serviceKeyType", None
                        ),
                        # providerDetails
                        # certificates
                        # domains
                        # ips
                        # classifications
                        # tlsVersions
                        "cves": cves
                        # enrichedObservationSource
                        # ip_ranges
                    }
                )

    alert_dict = {
        "time_pulled_from_xpanse": datetime.datetime.utcnow().replace(tzinfo=pytz.utc),
        "alert_id": alert.get("alert_id", None),
        "detection_timestamp": alert.get("detection_timestamp", None),
        "alert_name": alert.get("name", None),
        # endpoint_id ???,
        "description": alert.get("description", None),
        # "endpoint_id": alert.get('endpoint_id', None),
        # "host_ip": alert.get('host_ip', None),
        "host_name": alert.get("host_name", None),
        "alert_action": alert.get("action", None),
        # user_name ??? null,
        # mac_addresses ??? null,
        # source ??? null,
        "action_pretty": alert.get("action_pretty", None),
        # category ??? null,
        # project ??? null,
        # cloud_provider ??? null,
        # resource_sub_type ??? null,
        # resource_type ??? null,
        "action_country": alert.get("action_country", None),  # list type
        # event_type ??? null,
        # is_whitelisted ??? null,
        # image_name ??? null,
        # action_local_ip ??? null,
        # action_local_port ??? null,
        # action_external_hostname ??? null,
        # action_remote_ip ??? null,
        "action_remote_port": alert.get("action_remote_port", None),  # list type
        # "matching_service_rule_id ??? null,
        "starred": alert.get("starred", None),
        "external_id": alert.get("external_id", None),
        "related_external_id": None,
        "alert_occurrence": None,
        "severity": alert.get("severity", None),
        "matching_status": alert.get("matching_status", None),
        # end_match_attempt_ts ??? null,
        "local_insert_ts": alert.get("local_insert_ts", None),
        "last_modified_ts": alert.get("last_modified_ts", None),
        "case_id": alert.get("case_id", None),
        # deduplicate_tokens ??? null,
        # filter_rule_id ??? null,
        # event_id ??? null,
        "event_timestamp": alert.get("event_timestamp", None),  # list type
        # action_local_ip_v6 ??? null,
        # action_remote_ip_v6 ??? null,
        "alert_type": alert.get("alert_type", None),
        "resolution_status": alert.get("resolution_status", None),
        "resolution_comment": alert.get("resolution_comment", None),
        # dynamic_fields ??? null,
        "tags": alert.get("tags", None),
        # malicious_urls ??? null,
        "last_observed": alert.get("last_observed", None),
        "country_codes": alert.get("country_codes", None),  # list type
        "cloud_providers": alert.get("cloud_providers", None),  # list type
        "ipv4_addresses": alert.get("ipv4_addresses", None),  # list type
        # ipv6_addresses ??? null,
        "domain_names": alert.get("domain_names", None),  # list type
        "service_ids": alert.get("service_ids", None),  # already addressed above
        # "website_ids": alert.get('website_ids', None),
        "asset_ids": alert.get("asset_ids", None),  # list type
        "certificate": alert.get("certificate", None),
        # {
        #            issuerName": "IOS-Self-Signed-Certificate-782645061",
        #            subjectName": "IOS-Self-Signed-Certificate-782645061",
        #            validNotBefore": 1398850008000,
        #            validNotAfter": 1577836800000,
        #            serialNumber": "1"
        # },
        "port_protocol": alert.get("port_protocol", None),
        # business_unit_hierarchies
        # "business_unit_hierarchies": alert.get('business_unit_hierarchies', None), #list of BUs
        # attack_surface_rule_name ??? null,
        # remediation_guidance ??? null,
        "attack_surface_rule_name": alert.get("attack_surface_rule_name", None),
        "remediation_guidance": alert.get("remediation_guidance", None),
        "asset_identifiers": alert.get(
            "asset_identifiers", None
        ),  # messy list of objects
        "business_units": business_units_list,
        "services": services,
        "assets": assets,
    }

    if alert_dict["external_id"] is not None:
        alert_dict["related_external_id"] = "-".join(
            alert_dict["external_id"].split("-")[:-1]
        )
        alert_dict["alert_occurrence"] = (
            int(alert_dict["external_id"].split("-")[-1]) / 2
        )
    else:
        alert_dict["related_external_id"] = None
        alert_dict["alert_occurrence"] = None

    return alert_dict


def insert_business_units(business_unit_file):
    """Insert business unit into database from passed file."""
    try:
        reader = csv.DictReader(business_unit_file)
        org_dict = {}
        for dictionary in reader:
            business_unit_dict = {
                "entity_name": dictionary["Entity Name"].strip(),
                "state": dictionary["State"].strip(),
                "county": dictionary["County"].strip(),
                "city": dictionary["City"].strip(),
                "sector": dictionary["Sector"].strip(),
                "entity_type": dictionary["Entity Type"].strip(),
                "region": dictionary["Region"].strip(),
                "rating": int(dictionary["Rating"].strip()),
            }

            response = insert_or_update_business_unit(business_unit_dict)
            org_dict[response["business_unit_obj"]["entity_name"]] = response[
                "business_unit_obj"
            ]["xpanse_business_unit_uid"]

        return org_dict
    except FileNotFoundError:
        LOGGER.error("No file found at provided filepath.")
    except Exception as e:
        LOGGER.error("Unknown error: %s", e)


def pull_service_data(service_id_list):
    """Pull service info from the Xpanse API using a service_id."""
    url = xpanse_url + "v1/assets/get_external_service"
    request_data = {"service_id_list": service_id_list}

    payload = json.dumps({"request_data": request_data})

    headers = {
        "x-xdr-auth-id": auth_id,
        "Authorization": api_key,
        "Content-Type": "application/json",
    }

    response = requests.request("POST", url, headers=headers, data=payload)

    resp_dict = response.json()

    return resp_dict.get("reply", {}).get("details", None)


def run_xpanse_scans(last_modified, orgs_list, xpanse_org_csv):
    """Run Xpanse scans."""
    if orgs_list != "all":
        orgs_list = orgs_list.split(";")
    else:
        orgs_list = []

    org_dict = insert_business_units(xpanse_org_csv)
    pull_alerts_data(org_dict, orgs_list)
    # api_pull_xpanse_vulns(orgs_list[0], datetime.datetime(2023, 10, 10, 1, 00))

    return 1


def main():
    """Launch Xpanse scans."""
    args: Dict[str, str] = docopt.docopt(__doc__, version=__version__)

    schema: Schema = Schema(
        {
            "--log-level": And(
                str,
                Use(str.lower),
                lambda n: n in ("debug", "info", "warning", "error", "critical"),
                error="Possible values for --log-level are "
                + "debug, info, warning, error, and critical.",
            ),
            "XPANSE_ORG_CSV_PATH": Or(
                None,
                Use(open, error="XPANSE_ORG_CSV_PATH should point to a readable CSV"),
            ),
            str: object,  # Don't care about other keys, if any
        }
    )

    try:
        validated_args: Dict[str, Any] = schema.validate(args)
    except SchemaError as err:
        # Exit because one or more of the arguments were invalid
        print(err, file=sys.stderr)
        sys.exit(1)

    # Assign validated arguments to variables
    log_level: str = validated_args["--log-level"]

    # Set up logging
    logging.basicConfig(
        filename=pe_reports.CENTRAL_LOGGING_FILE,
        filemode="a",
        format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
        datefmt="%m/%d/%Y %I:%M:%S",
        level=log_level.upper(),
    )

    run_xpanse_scans(
        validated_args["--last_modified"],
        validated_args["--orgs"],
        validated_args["XPANSE_ORG_CSV_PATH"],
    )


if __name__ == "__main__":
    main()
