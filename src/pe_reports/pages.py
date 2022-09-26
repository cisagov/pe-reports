"""Collect and distribute graphical data to readable charts in the presentation."""

# Standard Python Libraries
import datetime
import logging
import os

# Third-Party Libraries
import chevron

from .charts import Charts

# Import Classes
from .metrics import Credentials, Cyber_Six, Domains_Masqs, Malware_Vulns


# Style and build tables
def buildTable(
    df, classList, sizingList=[], link_to_appendix=False, link_destination=False
):
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
            if link_to_appendix:
                if col == 0:
                    body += (
                        "<td style='width:{size}%'><a href='#{link}'>".format(
                            size=str(sizingList[col]),
                            link=str(row[col]).replace(" ", "_"),
                        )
                        + str(row[col])
                        + "</a></td>\n"
                    )
                else:
                    body += (
                        "<td style='width:{size}%'>".format(
                            size=str(sizingList[col]),
                        )
                        + str(row[col])
                        + "</td>\n"
                    )
            elif link_destination:
                if col == 0:
                    body += (
                        "<td style='width:{size}%'><a name='{link}'></a>".format(
                            size=str(sizingList[col]),
                            link=str(row[col]).replace(" ", "_"),
                        )
                        + str(row[col])
                        + "</td>\n"
                    )
                else:
                    body += (
                        "<td style='width:{size}%'>".format(
                            size=str(sizingList[col]),
                        )
                        + str(row[col])
                        + "</td>\n"
                    )
            else:
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
        html += """<p class="content"><b style="font-size: 15px;"><a name="{link_name}"></a>{breach_name}</b><br>{description}
        </p>\n""".format(
            breach_name=row[0], description=row[1], link_name=row[0].replace(" ", "_")
        )
    html += "\n</div>"
    return html


def credential(
    chevron_dict, trending_start_date, start_date, end_date, org_uid, source_html
):
    """Build exposed credential page."""
    Credential = Credentials(trending_start_date, start_date, end_date, org_uid)
    # Build exposed credential stacked bar chart
    width = 24
    height = 9
    name = "inc_date_df"
    title = "Trending Exposures by Week"
    x_label = "Week Reported"
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
    cred_date_chart.line_chart()
    breach_table = buildTable(
        Credential.breach_details(), ["table"], link_to_appendix=True
    )

    creds_dict = {
        "breach": Credential.breaches(),
        "creds": Credential.total(),
        "pw_creds": Credential.password(),
        "breach_table": breach_table,
    }
    breach_appendix = Credential.breach_appendix()

    if len(breach_appendix) > 0:
        # breach_appendix_list = np.array_split(breach_appendix.reset_index(drop=True),2)
        rows = 6
        n_pages = int(len(breach_appendix) / rows)
        frames = [
            breach_appendix.iloc[i * rows : (i + 1) * rows].copy()
            for i in range(n_pages + 1)
        ]
        # Load source HTML
        try:
            basedir = os.path.abspath(os.path.dirname(__file__))
            template = os.path.join(basedir, "template_breach_app.html")
            file = open(template)
            appendix_html = file.read().replace("\n", " ")
            # Close PDF
            file.close()
        except FileNotFoundError:
            logging.error("Template cannot be found. It must be named: '%s'", template)
            return 1
        i = 0
        for chunk in frames:
            key = "breachAppendix" + str(i)
            appendix_html_1 = appendix_html % (key)

            source_html = source_html + appendix_html_1
            creds_dict[key] = buildAppendixList(chunk)
            i += 1

    chevron_dict.update(creds_dict)

    return chevron_dict, Credential.creds_view, source_html


def masquerading(chevron_dict, start_date, end_date, org_uid):
    """Build masquerading page."""
    Domain_Masq = Domains_Masqs(start_date, end_date, org_uid)
    chevron_dict.update(
        {
            "domain_table": buildTable(Domain_Masq.summary(), ["table"], []),
            "domain_alerts_table": buildTable(
                Domain_Masq.alerts(), ["table"], [75, 25]
            ),
            "suspectedDomains": Domain_Masq.count(),
            "domain_alerts": Domain_Masq.alert_count(),
        }
    )
    return chevron_dict, Domain_Masq.df_mal, Domain_Masq.alerts_sum()


def mal_vuln(chevron_dict, start_date, end_date, org_uid, source_html):
    """Build Malwares and Vulnerabilities page."""
    Malware_Vuln = Malware_Vulns(start_date, end_date, org_uid)
    # Build insecure protocol horizontal bar chart
    width = 9
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
    width = 9
    height = 9
    name = "unverif_vuln_count"
    title = ""
    x_label = "Unverified CVEs"
    y_label = ""
    unverif_vuln_chart = Charts(
        Malware_Vuln.unverified_cve_count(),
        width,
        height,
        name,
        title,
        x_label,
        y_label,
    )
    unverif_vuln_chart.h_bar()
    # Build tables
    risky_assets = Malware_Vuln.insecure_protocols()
    risky_assets = risky_assets[:4]
    risky_assets.columns = ["Protocol", "IP", "Port"]
    risky_assets_table = buildTable(risky_assets, ["table"], [30, 40, 30])
    verif_vulns = Malware_Vuln.verif_vulns()
    verif_vulns.columns = ["CVE", "IP", "Port"]
    verif_vulns_table = buildTable(
        verif_vulns, ["table"], [40, 40, 20], link_to_appendix=True
    )

    # Update chevron dictionary
    vulns_dict = {
        "verif_vulns": verif_vulns_table,
        "risky_assets": risky_assets_table,
        "riskyPorts": Malware_Vuln.risky_ports_count(),
        "verifVulns": Malware_Vuln.total_verif_vulns(),
        "unverifVulns": Malware_Vuln.unverified_vuln_count(),
    }

    verif_vulns_summary = Malware_Vuln.verif_vulns_summary()
    if len(verif_vulns_summary) > 0:

        verif_vulns_summary_table = buildTable(
            verif_vulns_summary,
            ["table"],
            [15, 15, 15, 55],
            link_destination=True,
        )
        try:
            basedir = os.path.abspath(os.path.dirname(__file__))
            template = os.path.join(basedir, "template_vuln_app.html")
            file = open(template)
            vuln_html = file.read().replace("\n", " ")
            # Close PDF
            file.close()
        except FileNotFoundError:
            logging.error("Template cannot be found. It must be named: '%s'", template)
            return 1
        source_html = source_html + vuln_html
        vulns_dict["verif_vulns_summary"] = verif_vulns_summary_table

    chevron_dict.update(vulns_dict)
    return (
        chevron_dict,
        Malware_Vuln.insecure_df,
        Malware_Vuln.vulns_df,
        Malware_Vuln.assets_df,
        source_html,
    )


def dark_web(chevron_dict, trending_start_date, start_date, end_date, org_uid):
    """Dark Web Mentions."""
    Cyber6 = Cyber_Six(trending_start_date, start_date, end_date, org_uid)
    # Build dark web mentions over time line chart
    width = 18.5
    height = 8
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

    # Build tables
    dark_web_sites_table = buildTable(Cyber6.dark_web_sites(), ["table"], [50, 50])
    alerts_threats_table = buildTable(Cyber6.alerts_threats(), ["table"], [40, 40, 20])
    dark_web_actors_table = buildTable(
        Cyber6.dark_web_bad_actors()[:10], ["table"], [50, 50]
    )
    alerts_exec_table = buildTable(Cyber6.alerts_exec()[:8], ["table"], [15, 70, 15])
    asset_alerts_table = buildTable(Cyber6.asset_alerts()[:10], ["table"], [15, 70, 15])
    dark_web_act_table = buildTable(Cyber6.dark_web_most_act(), ["table"], [75, 25])
    social_med_act_table = buildTable(
        Cyber6.social_media_most_act(), ["table"], [75, 25]
    )
    invite_only_markets_table = buildTable(
        Cyber6.invite_only_markets(), ["table"], [50, 50]
    )
    top_cves_table = buildTable(Cyber6.top_cve_table(), ["table"], [15, 70, 15])

    dark_web_dict = {
        "darkWeb": Cyber6.dark_web_count(),
        "dark_web_sites": dark_web_sites_table,
        "alerts_threats": alerts_threats_table,
        "dark_web_actors": dark_web_actors_table,
        "alerts_exec": alerts_exec_table,
        "asset_alerts": asset_alerts_table,
        "dark_web_act": dark_web_act_table,
        "social_med_act": social_med_act_table,
        "markets_table": invite_only_markets_table,
        "top_cves": top_cves_table,
    }

    chevron_dict.update(dark_web_dict)
    return (chevron_dict, Cyber6.dark_web_mentions, Cyber6.alerts, Cyber6.top_cves)


def init(datestring, org_name, org_uid):
    """Call each page of the report."""
    # Format start_date and end_date for the bi-monthly reporting period.
    # If the given end_date is the 15th, then the start_date is the 1st.
    # Otherwise, the start_date will be the 16th of the respective month.

    # Load source HTML
    try:
        basedir = os.path.abspath(os.path.dirname(__file__))
        template = os.path.join(basedir, "template.html")
        file = open(template)
        source_html = file.read().replace("\n", " ")
        # Close PDF
        file.close()
    except FileNotFoundError:
        logging.error("Template cannot be found. It must be named: '%s'", template)
        return 1

    end_date = datetime.datetime.strptime(datestring, "%Y-%m-%d").date()
    if end_date.day == 15:
        start_date = datetime.datetime(end_date.year, end_date.month, 1)
    else:
        start_date = datetime.datetime(end_date.year, end_date.month, 16)
    days = datetime.timedelta(27)
    trending_start_date = end_date - days
    # Get base directory to save images
    base_dir = os.path.abspath(os.path.dirname(__file__))
    start = start_date.strftime("%m/%d/%Y")
    end = end_date.strftime("%m/%d/%Y")
    chevron_dict = {
        "department": org_name,
        "dateRange": start + " - " + end,
        "endDate": end,
        "base_dir": base_dir,
    }

    chevron_dict, creds_sum, source_html = credential(
        chevron_dict, trending_start_date, start_date, end_date, org_uid, source_html
    )

    chevron_dict, masq_df, dom_alert_sum = masquerading(
        chevron_dict, start_date, end_date, org_uid
    )

    chevron_dict, insecure_df, vulns_df, assets_df, source_html = mal_vuln(
        chevron_dict, start_date, end_date, org_uid, source_html
    )

    chevron_dict, dark_web_mentions, alerts, top_cves = dark_web(
        chevron_dict, trending_start_date, start_date, end_date, org_uid
    )
    source_html = (
        source_html
        + """
    </body>

    </html>
    """
    )
    html = chevron.render(source_html, chevron_dict)

    return (
        html,
        creds_sum,
        masq_df,
        dom_alert_sum,
        insecure_df,
        vulns_df,
        assets_df,
        dark_web_mentions,
        alerts,
        top_cves,
    )
