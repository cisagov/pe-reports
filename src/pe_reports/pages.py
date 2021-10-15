"""Collect and distribute graphical data to readable charts in the presentation."""

# Standard Python Libraries
from datetime import datetime

# Third-Party Libraries
from charts import barCharts
import chevron


# style and build tables
def buildTable(df, classList, sizingList=[]):
    """Build tables."""
    if not sizingList:
        average = 100 / len(df.columns)
        for x in df.columns:
            sizingList.append(average)
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
    """Build appendix."""
    html = "<div> \n"

    for row in df.itertuples(index=False):
        html += """<p class="content"><b style="font-size: 15px;">{breach_name}</b><br>{description}
        </p>\n""".format(
            breach_name=row[0], description=row[1]
        )
    html += "\n</div>"
    return html


def credential(
    chevron_dict, creds, breach, pw_creds, ce_date_df, breach_det_df, breach_appendix
):
    """Build credential page."""
    barCharts.stacked_bar(
        ce_date_df,
        "Reported Exposures by Day",
        "Date Reported",
        "Creds Exposed",
        24,
        9.5,
        "inc_date_df",
    )
    breach_table = buildTable(breach_det_df, ["table"])

    creds_dict = {
        "breach": breach,
        "creds": creds,
        "pw_creds": pw_creds,
        "breach_table": breach_table,
        "breachAppendix": buildAppendixList(breach_appendix),
    }
    chevron_dict.update(creds_dict)

    return chevron_dict


def masquerading(chevron_dict, domain_sum, domain_count, utlds):
    """Build masquerading page."""
    # build_table
    domain_table = buildTable(domain_sum, ["table"], [])
    chevron_dict.update(
        {
            "domain_table": domain_table,
            "suspectedDomains": domain_count,
            "uniqueTlds": utlds,
        }
    )
    return chevron_dict


def mal_vul(
    chevron_dict,
    pro_count,
    unverif_df,
    risky_assets,
    verif_vulns,
    verif_vulns_summary,
    riskyPortsCount,
    verifVulns,
    unverifVulnAssets,
):
    """Page 5: Malware Activity & Vulnerabilities."""
    # build charts
    barCharts.h_bar(pro_count, "", "", 9, 4.7, "pro_count", 1)
    barCharts.h_bar(unverif_df, "Unverified CVEs", "", 9, 9, "unverif_vuln_count", 1)
    # build tables
    risky_assets = risky_assets[:7]
    risky_assets.columns = ["IP", "Protocol"]
    risky_assets_table = buildTable(risky_assets, ["table"], [50, 50])
    # print(verif_vulns)
    verif_vulns.columns = ["CVE", "IP", "Port"]
    verif_vulns_table = buildTable(verif_vulns, ["table"], [40, 40, 20])
    verif_vulns_summary_table = buildTable(
        verif_vulns_summary, ["table"], [15, 15, 15, 55]
    )
    # update chevrion dictionary
    vulns_dict = {
        "verif_vulns": verif_vulns_table,
        "verif_vulns_summary": verif_vulns_summary_table,
        "risky_assets": risky_assets_table,
        "riskyPorts": riskyPortsCount,
        "verifVulns": verifVulns,
        "unverifVulns": unverifVulnAssets,
    }
    chevron_dict.update(vulns_dict)
    return chevron_dict


def dark_web(
    chevron_dict,
    dark_web_mentions,
    alerts_threats,
    top_cves,
):
    """Page 6: Web & Dark Web Mentions."""
    # Key Metric Output
    # key_metric_frame = Paragraph.text_frame_key_metric(prs, slide, shape, "TextBox 39")
    # frame = key_metric_frame.paragraphs[0]
    # run = frame.add_run()
    # run.text = (
    #     str(web)
    #     + " web and dark web mentions"
    #     + "\n"
    #     + "\n"
    #     + str(dark)
    #     + " mentions from tor or i2p associated sources"
    # )
    # font = run.font
    # font = Paragraph.text_style_key_metric(prs, font)

    # Line Chart - Web and “dark” web mentions over time
    # showAxis = True
    # small = False
    # barCharts.line_chart(dark_web_mentions, 19, 9, "web_only_df2", showAxis, small)
    # darkWeb = dark_web_mentions["date"].sum()
    # print(dark_web_mentions)

    # Bar Chart - Mentions categorized by source
    # title = ""
    # xAxisLabel = "Source of Mention"
    # yAxisLabel = "Mentions Count"
    # barCharts.simple_bar(
    #     web_source_df,
    #     title,
    #     xAxisLabel,
    #     yAxisLabel,
    #     18,
    #     5,
    #     "web_source_df",
    #     web,
    #     rotate_axis=True,
    #     grid=True,
    # )

    # Pie Chart - Forum Type / Conversation Content

    # title = ""
    # xAxisLabel = ""
    # yAxisLabel = ""
    # barCharts.pie(
    #     dark_web_content,
    #     title,
    #     xAxisLabel,
    #     yAxisLabel,
    #     19,
    #     9,
    #     "dark_web_forum_pie",
    #     len(dark_web_content),
    # )

    # build tables

    # Clean data
    # dark_web_bad_actors = dark_web_bad_actors[["creator", "rep_grade"]]

    # alerts_exec = alerts_exec.sort_values(by="alert_name.1", ascending=False)
    # alerts_exec = alerts_exec[["site", "title", "alert_name.1"]]

    # dark_web_act = dark_web_act[["comments_count", "title", "content"]]
    # dark_web_act = dark_web_act.sort_values(by="comments_count", ascending=False)
    # dark_web_act = dark_web_act.rename(columns={"comments_count": "Events"})

    # top_cves = top_cves[["cve_id", "nvd_base_score"]]

    # dark_web_sites_table = buildTable(dark_web_sites, ["table"], [50, 50])
    # alerts_threats_table = buildTable(alerts_threats, ["table"], [40, 40, 20])
    # dark_web_actors_table = buildTable(dark_web_bad_actors[:10], ["table"], [50, 50])
    # dark_web_tags_table = buildTable(dark_web_tags, ["table"], [60, 40])
    # alerts_exec_table = buildTable(alerts_exec[:10], ["table"], [15, 70, 15])
    # dark_web_act_table = buildTable(dark_web_act[:4], ["table"], [10, 20, 70])
    # top_cves_table = buildTable(top_cves, ["table"], [30, 70])

    dark_web_dict = {
        # "darkWeb": darkWeb,
        # "dark_web_sites": dark_web_sites_table,
        # "alerts_threats": alerts_threats_table,
        # "dark_web_actors": dark_web_actors_table,
        # "dark_web_tags": dark_web_tags_table,
        # "alerts_exec": alerts_exec_table,
        # "dark_web_act": dark_web_act_table,
        # "top_cves": top_cves_table,
    }

    chevron_dict.update(dark_web_dict)

    return chevron_dict


def init(
    source_html,
    datestring,
    org_name,
    folder_name,
    creds,
    breach,
    pw_creds,
    ce_date_df,
    breach_det_df,
    creds_attach,
    breach_appendix,
    domain_sum,
    domain_count,
    utlds,
    pro_count,
    unverif_df,
    risky_assets,
    verif_vulns,
    verif_vulns_summary,
    riskyPortsCount,
    verifVulns,
    unverifVulnAssets,
    dark_web_mentions,
    alerts_threats,
    top_cves,
):
    """Initialize pages."""
    end_date = datetime.strptime(datestring, "%Y-%m-%d").date()
    if end_date.day == 15:
        start = datetime(end_date.year, end_date.month, 1)
    else:
        start = datetime(end_date.year, end_date.month, 16)
    start = start.strftime("%m/%d/%Y")
    end = end_date.strftime("%m/%d/%Y")
    chevron_dict = {
        "department": org_name,
        "dateRange": start + " - " + end,
        "endDate": end,
    }

    chevron_dict = credential(
        chevron_dict,
        creds,
        breach,
        pw_creds,
        ce_date_df,
        breach_det_df,
        breach_appendix,
    )
    chevron_dict = masquerading(chevron_dict, domain_sum, domain_count, utlds)
    chevron_dict = mal_vul(
        chevron_dict,
        pro_count,
        unverif_df,
        risky_assets,
        verif_vulns,
        verif_vulns_summary,
        riskyPortsCount,
        verifVulns,
        unverifVulnAssets,
    )
    chevron_dict = dark_web(
        chevron_dict,
        dark_web_mentions,
        alerts_threats,
        top_cves,
    )
    html = chevron.render(source_html, chevron_dict)
    return html
