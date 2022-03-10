"""Collect and distribute graphical data to readable charts in the presentation."""

# Standard Python Libraries
import datetime

# Third-Party Libraries
from charts import Charts
import chevron

# Import Classes
from metrics import Credentials, Cyber_Six, Domains_Masqs, Malware_Vulns


# Style and build tables
def buildTable(df, classList, sizingList=[]):
    """Build HTML tables from a pandas dataframe."""
    # SizingList specifies the proportional width of each column.
    # The number of integers in the list must equal the number of
    # columns in the dataframe AND add up to 100
    if not sizingList:
        average = 100 / len(df.columns)
        sizingList = [average] * len(df.columns)
    headers = """<table border="1" class="{classes}">\n<thead>\n""".format(
        classes=", ".join(classList)
    )
    headers += '<tr style="text-align: right;">'
    for head in df.columns:
        headers += "<th>" + head + "</th>\n"
    headers += "</tr>\n</thead>"
    html = ""
    body = "<tbody>\n"
    counter = 0
    for row in df.itertuples(index=False):
        if counter % 2 == 0:
            body += '<tr class="even">\n'
        else:
            body += '<tr class="odd">\n'
        for col in range(0, len(df.columns)):
            body += (
                "<td style='width:{size}%'>".format(size=str(sizingList[col]))
                + str(row[col])
                + "</td>\n"
            )

        body += "</tr>\n"
        counter += 1
    body += "</tbody>\n</table>"
    html = headers + body
    return html


def buildAppendixList(df):
    """Build report appendix."""
    html = "<div> \n"

    for row in df.itertuples(index=False):
        html += """<p class="content"><b style="font-size: 15px;">{breach_name}</b><br>{description}
        </p>\n""".format(
            breach_name=row[0], description=row[1]
        )
    html += "\n</div>"
    return html


def credential(chevron_dict, trending_start_date, start_date, end_date, org_uid):
    """Build exposed credential page."""
    Credential = Credentials(trending_start_date, start_date, end_date, org_uid)
    # Build exposed credential stacked bar chart
    width = 24
    height = 9.5
    name = "inc_date_df"
    title = "Reported Exposures by Day"
    x_label = "Date Reported"
    y_label = "Creds Exposed"
    cred_date_chart = Charts(
        Credential.by_days(),
        width,
        height,
        name,
        title,
        x_label,
        y_label,
    )
    cred_date_chart.stacked_bar()
    breach_table = buildTable(Credential.breach_details(), ["table"])

    creds_dict = {
        "breach": Credential.breaches(),
        "creds": Credential.total(),
        "pw_creds": Credential.password(),
        "breach_table": breach_table,
        "breachAppendix": buildAppendixList(Credential.breach_appendix()),
    }
    chevron_dict.update(creds_dict)

    return chevron_dict, Credential.query_hibp_view, Credential.query_cyberSix_creds


def masquerading(chevron_dict, start_date, end_date, org_uid):
    """Build masquerading page."""
    Domain_Masq = Domains_Masqs(start_date, end_date, org_uid)
    chevron_dict.update(
        {
            "domain_table": buildTable(Domain_Masq.summary(), ["table"], []),
            "suspectedDomains": Domain_Masq.count(),
            "uniqueTlds": Domain_Masq.utlds(),
        }
    )
    return chevron_dict, Domain_Masq.df_mal


def mal_vuln(chevron_dict, start_date, end_date, org_uid):
    """Build Malwares and Vulnerabilities page."""
    Malware_Vuln = Malware_Vulns(start_date, end_date, org_uid)
    # Build insecure protocol horizontal bar chart
    width = 9
    height = 4.7
    name = "pro_count"
    title = ""
    x_label = ""
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
    width = 9
    height = 4.7
    name = "unverif_vuln_count"
    title = ""
    x_label = "Unverified CVEs"
    y_label = ""
    unverif_vuln_chart = Charts(
        Malware_Vuln.unverified_cve(),
        width,
        height,
        name,
        title,
        x_label,
        y_label,
    )
    unverif_vuln_chart.h_bar()
    # Build tables
    risky_assets = Malware_Vuln.isolate_risky_assets(Malware_Vuln.insecure_df)
    risky_assets = risky_assets[:7]
    risky_assets.columns = ["IP", "Protocol"]
    risky_assets_table = buildTable(risky_assets, ["table"], [50, 50])
    verif_vulns = Malware_Vuln.verif_vulns()
    verif_vulns.columns = ["CVE", "IP", "Port"]
    verif_vulns_table = buildTable(verif_vulns, ["table"], [40, 40, 20])
    verif_vulns_summary_table = buildTable(
        Malware_Vuln.verif_vulns_summary(), ["table"], [15, 15, 15, 55]
    )

    # Update chevron dictionary
    vulns_dict = {
        "verif_vulns": verif_vulns_table,
        "verif_vulns_summary": verif_vulns_summary_table,
        "risky_assets": risky_assets_table,
        "riskyPorts": Malware_Vuln.risky_ports_count(),
        "verifVulns": Malware_Vuln.total_verif_vulns(),
        "unverifVulns": Malware_Vuln.unverified_vuln_count(),
    }
    chevron_dict.update(vulns_dict)
    return (
        chevron_dict,
        Malware_Vuln.insecure_df,
        Malware_Vuln.vulns_df,
        Malware_Vuln.assets_df,
    )


def dark_web(chevron_dict, start_date, end_date, org_uid):
    """Dark Web Mentions."""
    Cyber6 = Cyber_Six(start_date, end_date, org_uid)
    # Build dark web mentions over time line chart
    width = 19
    height = 9
    name = "web_only_df2"
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
    # Build forum type / conversation content pie chart
    width = 19
    height = 9
    name = "dark_web_forum_pie"
    title = ""
    x_label = ""
    y_label = ""
    pie_chart = Charts(
        Cyber6.dark_web_content(),
        width,
        height,
        name,
        title,
        x_label,
        y_label,
    )
    pie_chart.pie()

    # Limit the number of rows for large dataframes
    dark_web_bad_actors = Cyber6.dark_web_bad_actors()[:10]
    alert_exec = Cyber6.alerts_exec()[:8]

    # Build tables
    dark_web_sites_table = buildTable(Cyber6.dark_web_sites(), ["table"], [50, 50])
    alerts_threats_table = buildTable(Cyber6.alerts_threats(), ["table"], [40, 40, 20])
    dark_web_actors_table = buildTable(dark_web_bad_actors, ["table"], [50, 50])
    dark_web_tags_table = buildTable(Cyber6.dark_web_tags(), ["table"], [60, 40])
    alerts_exec_table = buildTable(alert_exec, ["table"], [15, 70, 15])
    dark_web_act_table = buildTable(Cyber6.dark_web_most_act(), ["table"], [75, 25])
    alerts_site_table = buildTable(Cyber6.alerts_site(), ["table"], [50, 50])
    top_cves_table = buildTable(Cyber6.top_cve_table(), ["table"], [30, 70])

    dark_web_dict = {
        "darkWeb": Cyber6.dark_web_count(),
        "dark_web_sites": dark_web_sites_table,
        "alerts_threats": alerts_threats_table,
        "dark_web_actors": dark_web_actors_table,
        "dark_web_tags": dark_web_tags_table,
        "alerts_exec": alerts_exec_table,
        "dark_web_act": dark_web_act_table,
        "alerts_site": alerts_site_table,
        "top_cves": top_cves_table,
    }

    chevron_dict.update(dark_web_dict)
    return (chevron_dict, Cyber6.dark_web_mentions, Cyber6.alerts, Cyber6.top_cves)


def init(source_html, datestring, org_name, org_uid):
    """Call each page of the report."""
    # Format start_date and end_date for the bi-monthly reporting period.
    # If the given end_date is the 15th, then the start_date is the 1st.
    # Otherwise, the start_date will be the 16th of the respective month.
    end_date = datetime.datetime.strptime(datestring, "%Y-%m-%d").date()
    days = datetime.timedelta(6)
    start_date = end_date - days
    days = datetime.timedelta(27)
    trending_start_date = end_date - days
    # if end_date.day == 15:
    #     start_date = datetime.datetime(end_date.year, end_date.month, 1)
    # else:
    #     start_date = datetime.datetime(end_date.year, end_date.month, 16)

    start = start_date.strftime("%m/%d/%Y")
    end = end_date.strftime("%m/%d/%Y")
    chevron_dict = {
        "department": org_name,
        "dateRange": start + " - " + end,
        "endDate": end,
    }

    chevron_dict, hibp_creds, cyber_creds = credential(
        chevron_dict, trending_start_date, start_date, end_date, org_uid
    )

    chevron_dict, masq_df = masquerading(chevron_dict, start_date, end_date, org_uid)

    chevron_dict, insecure_df, vulns_df, assets_df = mal_vuln(
        chevron_dict, start_date, end_date, org_uid
    )

    chevron_dict, dark_web_mentions, alerts, top_cves = dark_web(
        chevron_dict, start_date, end_date, org_uid
    )

    html = chevron.render(source_html, chevron_dict)

    return (
        html,
        hibp_creds,
        cyber_creds,
        masq_df,
        insecure_df,
        vulns_df,
        assets_df,
        dark_web_mentions,
        alerts,
        top_cves,
    )
