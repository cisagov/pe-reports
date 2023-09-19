"""Collect and distribute graphical data to readable charts in the presentation."""

# Standard Python Libraries
import datetime
import json
import logging
import os

# Third-Party Libraries
import pandas as pd

from .charts import Charts
from .data.db_query import sanitize_uid

# Import Classes
from .metrics import (
    Core_Cyber_Six,
    Credentials,
    Cyber_Six,
    Domains_Masqs,
    Malware_Vulns,
)

# Setup logging to central
LOGGER = logging.getLogger(__name__)


def credential(
    report_dict,
    trending_start_date,
    start_date,
    end_date,
    org_uid,
    org_code,
    output_directory,
):
    """Build exposed credential page."""
    Credential = Credentials(
        trending_start_date, start_date, end_date, sanitize_uid(org_uid)
    )
    # Build exposed credential stacked bar chart
    width = 16.51
    height = 10
    name = "inc_date_df"
    title = "Trending Exposures by Week"
    x_label = "Week Reported"
    y_label = "Creds Exposed"
    cred_date_chart = Charts(
        Credential.by_week(),
        width,
        height,
        name,
        title,
        x_label,
        y_label,
    )
    cred_date_chart.line_chart()
    # Filter breach details table down to top 15 rows.
    breach_table_row_count = 15
    creds_dict = {
        "breach": Credential.breaches(),
        "creds": Credential.total(),
        "pw_creds": Credential.password(),
        "breach_table": Credential.breach_details()[:breach_table_row_count],
        "breach_appendix": Credential.breach_appendix(),
    }
    report_dict.update(creds_dict)

    # Create Credential Exposure JSON file
    cred_json = f"{output_directory}/{org_code}/compromised_credentials.json"
    cred_dict = Credential.creds_view.to_dict(orient="records")
    final_dict = {"credentials": cred_dict}
    with open(cred_json, "w") as outfile:
        json.dump(final_dict, outfile, default=str)

    # Create Credential Exposure Excel file
    cred_xlsx = f"{output_directory}/{org_code}/compromised_credentials.xlsx"
    credWriter = pd.ExcelWriter(cred_xlsx, engine="xlsxwriter")
    Credential.creds_view.to_excel(credWriter, sheet_name="Credentials", index=False)
    credWriter.save()

    return report_dict, cred_json, cred_xlsx


def masquerading(
    report_dict, start_date, end_date, org_uid, org_code, output_directory
):
    """Build masquerading page."""
    Domain_Masq = Domains_Masqs(start_date, end_date, sanitize_uid(org_uid))
    report_dict.update(
        {
            "domain_table": Domain_Masq.summary()[:10],
            "domain_alerts_table": Domain_Masq.alerts()[:10],
            "suspectedDomains": Domain_Masq.count(),
            "domain_alerts": Domain_Masq.alert_count(),
        }
    )
    # Create Domain Masquerading JSON file
    da_json = f"{output_directory}/{org_code}/domain_alerts.json"
    susp_domains_dict = Domain_Masq.df_mal.to_dict(orient="records")
    dom_alerts_dict = Domain_Masq.alerts_sum().to_dict(orient="records")
    final_dict = {
        "suspected_domains": susp_domains_dict,
        "domain_alerts": dom_alerts_dict,
    }
    with open(da_json, "w") as outfile:
        json.dump(final_dict, outfile, default=str)

    # Create Domain Masquerading Excel file
    da_xlsx = f"{output_directory}/{org_code}/domain_alerts.xlsx"
    domWriter = pd.ExcelWriter(da_xlsx, engine="xlsxwriter")
    Domain_Masq.df_mal.to_excel(domWriter, sheet_name="Suspected Domains", index=False)
    Domain_Masq.alerts_sum().to_excel(
        domWriter, sheet_name="Domain Alerts", index=False
    )
    domWriter.save()
    return report_dict, da_json, da_xlsx


def mal_vuln(report_dict, start_date, end_date, org_uid, org_code, output_directory):
    """Build Malwares and Vulnerabilities page."""
    Malware_Vuln = Malware_Vulns(start_date, end_date, org_uid)
    # Build insecure protocol horizontal bar chart
    width = 16.51
    height = 5.3
    name = "pro_count"
    title = ""
    x_label = "Insecure Protocols"
    y_label = ""
    protocol_chart = Charts(
        Malware_Vuln.protocol_count(),
        width,
        height,
        name,
        title,
        x_label,
        y_label,
    )
    protocol_chart.h_bar()
    # Build unverified vulnerability horizontal bar chart
    width = 16.51
    height = 9
    name = "unverif_vuln_count"
    title = ""
    x_label = "Unverified CVEs"
    y_label = ""
    unverif_vuln_chart = Charts(
        Malware_Vuln.unverified_cv_count(),
        width,
        height,
        name,
        title,
        x_label,
        y_label,
    )
    unverif_vuln_chart.h_bar()
    unverif_vuln_chart.h_bar()
    # Build tables
    risky_assets = Malware_Vuln.insecure_protocols()
    risky_assets = risky_assets[:10]
    risky_assets.columns = ["Protocol", "IP", "Port"]
    verif_vulns = Malware_Vuln.verif_vulns()[:10]
    verif_vulns.columns = ["CVE", "IP", "Port"]
    risky_ports = Malware_Vuln.risky_ports_count()
    verif_vulns_count = Malware_Vuln.total_verif_vulns()
    unverif_vulns = Malware_Vuln.unverified_vuln_count()
    # Update chevron dictionary
    vulns_dict = {
        "verif_vulns": verif_vulns,
        "risky_assets": risky_assets,
        "riskyPorts": risky_ports,
        "verifVulns": verif_vulns_count,
        "unverifVulns": unverif_vulns,
        "verif_vulns_summary": Malware_Vuln.verif_vulns_summary(),
    }
    all_cves_df = Malware_Vuln.all_cves()
    report_dict.update(vulns_dict)

    # Create Suspected vulnerability JSON file
    vuln_json = f"{output_directory}/{org_code}/vuln_alerts.json"
    assets_dict = Malware_Vuln.assets_df.to_dict(orient="records")
    insecure_dict = Malware_Vuln.insecure_df.to_dict(orient="records")
    vulns_dict = Malware_Vuln.vulns_df.to_dict(orient="records")
    final_dict = {
        "assets": assets_dict,
        "insecure": insecure_dict,
        "verified_vulns": vulns_dict,
    }
    with open(vuln_json, "w") as outfile:
        json.dump(final_dict, outfile, default=str)

    # Create Suspected vulnerability Excel file
    vuln_xlsx = f"{output_directory}/{org_code}/vuln_alerts.xlsx"
    vulnWriter = pd.ExcelWriter(vuln_xlsx, engine="xlsxwriter")
    Malware_Vuln.assets_df.to_excel(vulnWriter, sheet_name="Assets", index=False)
    Malware_Vuln.insecure_df.to_excel(vulnWriter, sheet_name="Insecure", index=False)
    Malware_Vuln.vulns_df.to_excel(vulnWriter, sheet_name="Verified Vulns", index=False)
    vulnWriter.save()
    return (report_dict, vuln_json, all_cves_df, vuln_xlsx)


def dark_web(
    report_dict,
    trending_start_date,
    start_date,
    end_date,
    org_uid,
    all_cves_df,
    soc_med_included,
    org_code,
    output_directory,
):
    """Dark Web Mentions."""
    Cyber6 = Cyber_Six(
        trending_start_date,
        start_date,
        end_date,
        org_uid,
        all_cves_df,
        soc_med_included,
    )
    # Build dark web mentions over time line chart
    width = 16.51
    height = 10
    name = "web_only_df_2"
    title = ""
    x_label = "Dark Web Mentions"
    y_label = "Mentions count"
    dark_mentions_chart = Charts(
        Cyber6.dark_web_date(),
        width,
        height,
        name,
        title,
        x_label,
        y_label,
    )
    dark_mentions_chart.line_chart()

    # Limit the number of rows for large dataframes
    dark_web_actors = Cyber6.dark_web_bad_actors()

    social_media = Cyber6.social_media_most_act()
    if not soc_med_included:
        social_media = social_media[0:0]
    dark_web_dict = {
        "darkWeb": Cyber6.dark_web_count(),
        "mentions_count": Cyber6.dark_web_mentions_count(),
        "dark_web_sites": Cyber6.dark_web_sites(),
        "alerts_threats": Cyber6.alerts_threats(),
        "dark_web_actors": dark_web_actors,
        "alerts_exec": Cyber6.alerts_exec()[:10],
        "asset_alerts": Cyber6.asset_alerts()[:10],
        "dark_web_act": Cyber6.dark_web_most_act(),
        "social_med_act": social_media,
        "markets_table": Cyber6.invite_only_markets(),
        "top_cves": Cyber6.top_cve_table(),
    }

    report_dict.update(dark_web_dict)

    # Create dark web Excel file
    mentions_df = Cyber6.dark_web_mentions
    mentions_df["content"] = mentions_df["content"].str[:2000]
    mi_json = f"{output_directory}/{org_code}/mention_incidents.json"
    mentions_dict = mentions_df.to_dict(orient="records")
    alerts_dict = Cyber6.alerts.to_dict(orient="records")
    cve_dict = Cyber6.top_cves.to_dict(orient="records")
    final_dict = {
        "dark_web_mentions": mentions_dict,
        "dark_web_alerts": alerts_dict,
        "top_cves": cve_dict,
    }
    with open(mi_json, "w") as outfile:
        json.dump(final_dict, outfile, default=str)

    # Create dark web Excel file
    mi_xlsx = f"{output_directory}/{org_code}/mention_incidents.xlsx"
    miWriter = pd.ExcelWriter(mi_xlsx, engine="xlsxwriter")
    mentions_df.to_excel(miWriter, sheet_name="Dark Web Mentions", index=False)
    Cyber6.alerts.to_excel(miWriter, sheet_name="Dark Web Alerts", index=False)
    Cyber6.top_cves.to_excel(miWriter, sheet_name="Top CVEs", index=False)
    miWriter.save()

    return (report_dict, mi_json, mi_xlsx)


def init(
    datestring,
    org_name,
    org_code,
    org_uid,
    premium,
    output_directory,
    soc_med_included=False,
):
    """Call each page of the report."""
    # Format start_date and end_date for the bi-monthly reporting period.
    # If the given end_date is the 15th, then the start_date is the 1st.
    # Otherwise, the start_date will be the 16th of the respective month.

    end_date = datetime.datetime.strptime(datestring, "%Y-%m-%d").date()
    if end_date.day == 15:
        start_date = datetime.datetime(end_date.year, end_date.month, 1)
    else:
        start_date = datetime.datetime(end_date.year, end_date.month, 16)
    # create the trending start date which is 4 weeks from the last day of the report period
    # 27 days plus the last day is 4 weeks
    days = datetime.timedelta(27)
    trending_start_date = end_date - days

    # Get base directory to save images
    base_dir = os.path.abspath(os.path.dirname(__file__))
    start = start_date.strftime("%m/%d/%Y")
    end = end_date.strftime("%m/%d/%Y")
    report_dict = {
        "department": org_name,
        "dateRange": start + " - " + end,
        "endDate": end,
        "base_dir": base_dir,
    }
    # Fill credentials data
    (report_dict, cred_json, cred_xlsx) = credential(
        report_dict,
        trending_start_date,
        start_date,
        end_date,
        org_uid,
        org_code,
        output_directory,
    )

    # Domain Masquerading
    report_dict, da_json, da_xlsx = masquerading(
        report_dict,
        start_date,
        end_date,
        org_uid,
        org_code,
        output_directory,
    )

    # Inferred/Verified Vulnerabilities
    (report_dict, vuln_json, all_cves_df, vuln_xlsx) = mal_vuln(
        report_dict,
        start_date,
        end_date,
        org_uid,
        org_code,
        output_directory,
    )

    # Dark web mentions and alerts
    if premium:
        report_dict, mi_json, mi_xlsx = dark_web(
            report_dict,
            trending_start_date,
            start_date,
            end_date,
            org_uid,
            all_cves_df,
            soc_med_included,
            org_code,
            output_directory,
        )
    else:
        Core_Cyber = Core_Cyber_Six(all_cves_df)
        report_dict["top_cves"] = Core_Cyber.top_cve_table()
        mi_json = None
        mi_xlsx = None

    return (
        report_dict,
        cred_json,
        da_json,
        vuln_json,
        mi_json,
        cred_xlsx,
        da_xlsx,
        vuln_xlsx,
        mi_xlsx,
    )
