"""Collect and distribute graphical data to readable charts in the presentation."""

# Standard Python Libraries
from datetime import datetime
import os

# Third-Party Libraries
from pptx.util import Inches

from .charts import barCharts
from .stylesheet import Paragraph, Table


def cover(prs, org_name, start, end):
    """Page 1: Cover page of presentation."""
    slide = prs.slides[0]
    shape = Paragraph.shapes(prs, slide)
    text_frame = Paragraph.text_frame(prs, shape)
    frame = text_frame.paragraphs[0]
    run = frame.add_run()
    dates = f"{start} to {end}"
    run.text = "Prepared for: " + org_name + "\nReporting period: " + dates
    font = run.font
    font = Paragraph.text_style_title(prs, font)
    return prs


def overview(
    prs,
    creds,
    domains,
    malware,
    vulns,
    web,
    tld_df,
    inc_src_df,
    web_df,
    ma_act_df,
    iv_act_df,
    dark_web_df,
    web_only_df,
):
    """Page 2: Posture & Exposure Report Overview."""
    slide = prs.slides[1]
    shape = Paragraph.shapes(prs, slide)

    # Overeview Value - Credentials exposed in recent posts
    ov_val_01 = Paragraph.text_frame_ov_val(prs, slide, shape, "TextBox 2")
    frame = ov_val_01.paragraphs[0]
    run = frame.add_run()
    run.text = str(creds)
    font = run.font
    font = Paragraph.text_style_ov_val(prs, font)

    # Overeview Value - Suspected domain masquerading alerts
    ov_val_02 = Paragraph.text_frame_ov_val(prs, slide, shape, "TextBox 82")
    frame = ov_val_02.paragraphs[0]
    run = frame.add_run()
    run.text = str(domains)
    font = run.font
    font = Paragraph.text_style_ov_val(prs, font)

    # Overeview Value - Active malware associations
    ov_val_03 = Paragraph.text_frame_ov_val(prs, slide, shape, "TextBox 86")
    frame = ov_val_03.paragraphs[0]
    run = frame.add_run()
    run.text = str(malware)
    font = run.font
    font = Paragraph.text_style_ov_val(prs, font)

    # Overeview Value - Web and dark web mentions
    ov_val_04 = Paragraph.text_frame_ov_val(prs, slide, shape, "TextBox 87")
    frame = ov_val_04.paragraphs[0]
    run = frame.add_run()
    run.text = str(vulns)
    font = run.font
    font = Paragraph.text_style_ov_val(prs, font)

    # Overeview Value - Credentials exposed in recent posts
    ov_val_05 = Paragraph.text_frame_ov_val(prs, slide, shape, "TextBox 90")
    frame = ov_val_05.paragraphs[0]
    run = frame.add_run()
    run.text = str(web)
    font = run.font
    font = Paragraph.text_style_ov_val(prs, font)

    # Bar Graph - Top Level Domains used for masquerading
    tld_short_df = tld_df[:5]
    if len(tld_short_df) == 5:
        rotate = True
    else:
        rotate = False
    x, y, cx, cy = Inches(3.25), Inches(2.8), Inches(2.5), Inches(1.6)
    title = ""
    name = barCharts.simple_bar(
        tld_short_df,
        title,
        "Top Level Domain",
        "",
        2.5,
        1.6,
        "tld_short_df",
        domains,
        rotate_axis=rotate,
        grid=False,
    )
    slide.shapes.add_picture(name + ".png", x, y, cx, cy)
    os.remove(name + ".png")

    # Bar Graph - Sources of credential exposures
    x, y, cx, cy = Inches(5.82), Inches(2.8), Inches(2.5), Inches(1.6)
    title = ""
    name = barCharts.simple_bar(
        inc_src_df,
        title,
        "Sources",
        "",
        2.5,
        1.6,
        "inc_src_df",
        creds,
        rotate_axis=False,
        grid=False,
    )
    slide.shapes.add_picture(name + ".png", x, y, cx, cy)
    os.remove(name + ".png")

    # Line Graph - Web and dark web mentions
    # chart = CategoryChartData()
    # chart.categories = web_only_df["Date of mention"]
    # chart.add_series("Web", web_only_df["Mentions count"])
    # chart.add_series("Dark web", dark_web_df["Mentions count"])

    x, y, cx, cy = Inches(3.25), Inches(5), Inches(5.0), Inches(2.3)
    # chart = slide.shapes.add_chart(XL_CHART_TYPE.LINE, x, y, cx, cy, chart).chart
    # chart = Graph.line_med(prs, slide, chart)
    showAxis = False
    small = True
    name = barCharts.line_chart(
        web_only_df, dark_web_df, 5, 2.3, "web_only_df", showAxis, small
    )
    slide.shapes.add_picture(name + ".png", x, y, cx, cy)
    os.remove(name + ".png")

    # Bar Graph - Active malware associations
    ma_act_df["Name"] = ma_act_df["Name"].str.split("-").str[0]
    x, y, cx, cy = Inches(8.5), Inches(2.7), Inches(4.5), Inches(2.4)
    title = "Malware Associations by Classification"
    name = barCharts.simple_bar(
        ma_act_df,
        title,
        "Classification",
        "Association Count",
        4.5,
        2.4,
        "ma_act_df",
        malware,
        rotate_axis=True,
        grid=True,
    )
    slide.shapes.add_picture(name + ".png", x, y, cx, cy)
    os.remove(name + ".png")

    # Bar Graph - inferred vulnerabilities found via external observation
    x, y, cx, cy = Inches(8.5), Inches(5), Inches(4.5), Inches(2.4)
    title = "Inferred Vulnerabilities by Classification"
    name = barCharts.simple_bar(
        iv_act_df,
        title,
        "Classification",
        "Vulnerability Count",
        4.5,
        2.4,
        "iv_act_df",
        vulns,
        rotate_axis=True,
        grid=True,
    )
    slide.shapes.add_picture(name + ".png", x, y, cx, cy)
    os.remove(name + ".png")

    return prs


def credential(prs, inc, creds, inc_src_df, inc_date_df, ce_inc_df):
    """Page 3: Credential Publication & Abuse."""
    slide = prs.slides[2]
    shape = Paragraph.shapes(prs, slide)

    # Key Metric Output
    key_metric_frame = Paragraph.text_frame_key_metric(prs, slide, shape, "TextBox 40")
    frame = key_metric_frame.paragraphs[0]
    run = frame.add_run()
    run.text = (
        str(creds)
        + " credentials published publicly in recent post"
        + "\n"
        + "\n"
        + str(inc)
        + " seperate incident(s) containing credentials found"
    )
    font = run.font
    font = Paragraph.text_style_key_metric(prs, font)

    # Line Graph 1 - Credential exposure incidents by date discovered
    inc_date_df = inc_date_df.reset_index(drop=True)
    inc_date_df = inc_date_df[["Date of discovery", "Incident count"]]
    x, y, cx, cy = Inches(3.5), Inches(1.4), Inches(9.2), Inches(2.8)
    title = ""
    xAxisLabel = "Date of Discovery"
    yAxisLabel = "Incident Count"
    name = barCharts.simple_bar(
        inc_date_df,
        title,
        xAxisLabel,
        yAxisLabel,
        9.2,
        2.8,
        "inc_date_df",
        creds,
        rotate_axis=True,
        grid=False,
    )
    slide.shapes.add_picture(name + ".png", x, y, cx, cy)
    os.remove(name + ".png")

    # Line Graph 2 - Credentials exposed count per incident
    x, y, cx, cy = Inches(3.5), Inches(4.8), Inches(5.6), Inches(2.7)
    ce_inc_df = ce_inc_df.reset_index(drop=True)
    ce_inc_df = ce_inc_df[["Credential count per incidents", "Incident count"]]
    title = ""
    xAxisLabel = "Credential count per incidents"
    yAxisLabel = "Incident Count"
    name = barCharts.simple_bar(
        ce_inc_df,
        title,
        xAxisLabel,
        yAxisLabel,
        5.6,
        2.7,
        "ce_inc_df",
        creds,
        rotate_axis=False,
        grid=False,
    )
    slide.shapes.add_picture(name + ".png", x, y, cx, cy)
    os.remove(name + ".png")

    # Line Graph 3 - Sources of credential exposure incidents
    x, y, cx, cy = Inches(9.90), Inches(4.8), Inches(2.8), Inches(2.7)
    title = ""
    xAxisLabel = "Source"
    yAxisLabel = "Count"
    name = barCharts.simple_bar(
        inc_src_df,
        title,
        xAxisLabel,
        yAxisLabel,
        2.8,
        2.7,
        "inc_src_df",
        creds,
        rotate_axis=False,
        grid=False,
    )
    slide.shapes.add_picture(name + ".png", x, y, cx, cy)
    os.remove(name + ".png")

    return prs


def masquerading(prs, domains, utld, tld_df, dm_df, dm_samp):
    """Page 4: Suspected Domain Masquerading."""
    slide = prs.slides[3]
    shape = Paragraph.shapes(prs, slide)

    # Key Metric Output
    key_metric_frame = Paragraph.text_frame_key_metric(prs, slide, shape, "TextBox 47")
    frame = key_metric_frame.paragraphs[0]
    run = frame.add_run()
    run.text = (
        str(domains)
        + " domains suspected of masquerading found"
        + "\n"
        + "\n"
        + str(utld)
        + " unique TLDs used by masquerading domains"
    )
    font = run.font
    font = Paragraph.text_style_key_metric(prs, font)

    # Line Graph 1 - Suspected domain masquerading by incident date of discovery
    x, y, cx, cy = Inches(3.5), Inches(1.4), Inches(9.2), Inches(2.8)
    title = ""
    xAxisLabel = "Date of Discovery"
    yAxisLabel = "Domain Count"
    name = barCharts.simple_bar(
        dm_df,
        title,
        xAxisLabel,
        yAxisLabel,
        9.2,
        2.8,
        "dm_df",
        domains,
        rotate_axis=True,
        grid=False,
    )
    slide.shapes.add_picture(name + ".png", x, y, cx, cy)
    os.remove(name + ".png")

    # Line Graph 2 - Top level domains used for suspected masquerading of agency assets
    if len(tld_df) > 5:
        rotate = True
    else:
        rotate = False
    tld_df = tld_df[:25]
    x, y, cx, cy = Inches(3.5), Inches(4.8), Inches(5.6), Inches(2.7)
    title = ""
    xAxisLabel = "Domain Count"
    yAxisLabel = "Top Level Domains (TLD)"
    name = barCharts.simple_bar(
        tld_df,
        title,
        xAxisLabel,
        yAxisLabel,
        5.6,
        2.7,
        "tld_df",
        domains,
        rotate_axis=rotate,
        grid=False,
    )
    slide.shapes.add_picture(name + ".png", x, y, cx, cy)
    os.remove(name + ".png")

    # Textbox 1 - Sample of domains suspected of masquerading
    sample_domain_frame = Paragraph.text_frame_key_metric(
        prs, slide, shape, "TextBox 1"
    )
    frame = sample_domain_frame.paragraphs[0]
    run = frame.add_run()
    sample_domains = ""
    if domains > 0:
        for index, row in dm_samp.iterrows():
            sample_domains += row["Suspected masquerading domains"] + "\n\n"
        run.text = sample_domains
        font = run.font
        font = Paragraph.text_style_summary(prs, font)

    return prs


def mal_vul(prs, ma_act_df, iv_act_df, vuln_ma_df, vuln_ma_df2, vulns, uma, assets):
    """Page 5: Malware Activity & Vulnerabilities."""
    slide = prs.slides[4]
    shape = Paragraph.shapes(prs, slide)

    # Key Metric Output
    key_metric_frame = Paragraph.text_frame_key_metric(prs, slide, shape, "TextBox 9")
    frame = key_metric_frame.paragraphs[0]
    run = frame.add_run()
    run.text = (
        str(assets)
        + " assets with malware/inferred vulnerability associations"
        + "\n"
        + "\n"
        + str(uma)
        + " unique malware threats found among associations"
        + "\n"
        + "\n"
        + str(vulns)
        + " vulnerabilities inferred via external scanning"
    )
    font = run.font
    font = Paragraph.text_style_key_metric(prs, font)

    # Bar Graph - Active malware associations with agency assets
    x, y, cx, cy = Inches(3.5), Inches(1.4), Inches(4.5), Inches(3.0)
    name = barCharts.h_bar(ma_act_df, "Association Count", "", 4.6, 3.0, "ma_act", uma)
    slide.shapes.add_picture(name + ".png", x, y, cx, cy)
    os.remove(name + ".png")

    # Bar Graph - Active inferred vulnerabilities on agency assets
    x, y, cx, cy = Inches(8.5), Inches(1.4), Inches(4.5), Inches(3.0)
    name = barCharts.h_bar(
        iv_act_df, "Vulnerability Count", "", 4.6, 3.0, "iv_act", vulns
    )
    slide.shapes.add_picture(name + ".png", x, y, cx, cy)
    os.remove(name + ".png")

    # Bar Graph - Date of last observation for active malware and inferred vulnerabilities
    x, y, cx, cy = Inches(3.3), Inches(4.75), Inches(4.9), Inches(2.8)
    name = barCharts.stacked_bar(
        vuln_ma_df,
        "Date of last observation",
        "Association Count",
        4.9,
        2.8,
        "vuln_ma",
        vulns + assets,
        rotate_axis=True,
    )
    slide.shapes.add_picture(name + ".png", x, y, cx, cy)
    os.remove(name + ".png")

    # Bar Graph - Total days between first and last observation for active malware and inferred vulnerabilities
    x, y, cx, cy = Inches(8.3), Inches(4.85), Inches(4.9), Inches(2.6)
    xLabel = "Days between first and last observation"
    name = barCharts.stacked_bar(
        vuln_ma_df2,
        xLabel,
        "Association Count",
        4.9,
        2.6,
        "vuln_ma_2",
        vulns + assets,
        rotate_axis=False,
    )
    slide.shapes.add_picture(name + ".png", x, y, cx, cy)
    os.remove(name + ".png")

    return prs


def dark_web(prs, web_df, web_source_df, web, dark, dark_web_df, web_only_df):
    """Page 6: Web & Dark Web Mentions."""
    slide = prs.slides[5]
    shape = Paragraph.shapes(prs, slide)
    # Key Metric Output
    key_metric_frame = Paragraph.text_frame_key_metric(prs, slide, shape, "TextBox 39")
    frame = key_metric_frame.paragraphs[0]
    run = frame.add_run()
    run.text = (
        str(web)
        + " web and dark web mentions"
        + "\n"
        + "\n"
        + str(dark)
        + " mentions from tor or i2p associated sources"
    )
    font = run.font
    font = Paragraph.text_style_key_metric(prs, font)

    # Line Chart - Web and “dark” web mentions over time
    x, y, cx, cy = Inches(3.4), Inches(1.4), Inches(9.2), Inches(2.8)
    showAxis = True
    small = False
    name = barCharts.line_chart(
        web_only_df, dark_web_df, 9.2, 2.8, "web_only_df", showAxis, small
    )
    slide.shapes.add_picture(name + ".png", x, y, cx, cy)
    os.remove(name + ".png")

    # Bar Chart - Mentions categorized by source
    x, y, cx, cy = Inches(3.4), Inches(4.7), Inches(9.2), Inches(2.8)
    title = ""
    xAxisLabel = "Source of Mention"
    yAxisLabel = "Mentions Count"
    name = barCharts.simple_bar(
        web_source_df,
        title,
        xAxisLabel,
        yAxisLabel,
        9.2,
        2.8,
        "web_source_df",
        web,
        rotate_axis=True,
        grid=True,
    )
    slide.shapes.add_picture(name + ".png", x, y, cx, cy)
    os.remove(name + ".png")

    return prs


def supplimental(prs, ma_samp, dm_samp, iv_samp):
    """Page 7: Supplemental Reports & Annex."""
    slide = prs.slides[6]
    shape = Paragraph.shapes(prs, slide)

    # ---add table 1---
    x, y, cx, cy = Inches(3.5), Inches(1.5), Inches(5.5), Inches(0.5)
    num_rows = len(ma_samp.index) + 1
    shape = slide.shapes.add_table(num_rows, 3, x, y, cx, cy)
    table = shape.table
    table.cell(0, 0).text = "Malware Associated Assets"
    table.cell(0, 1).text = "Classifications"
    table.cell(0, 2).text = "Date Last Observed"
    merge = False
    Table.summary_table(prs, table, num_rows, [0, 1, 2], ma_samp, merge)

    # ---add table 2---
    x, y, cx, cy = Inches(3.5), Inches(3.25), Inches(5.5), Inches(0.5)
    num_rows = len(dm_samp.index) + 1
    shape = slide.shapes.add_table(num_rows, 3, x, y, cx, cy)
    table = shape.table
    table.cell(0, 0).text = "Suspected Masquerading Domains"
    table.cell(0, 2).text = "Date Observed"
    merge = True
    Table.summary_table(prs, table, num_rows, [0, 2], dm_samp, merge)

    # ---add table 3---
    x, y, cx, cy = Inches(3.5), Inches(5), Inches(5.5), Inches(0.5)
    num_rows = len(iv_samp.index) + 1
    shape = slide.shapes.add_table(num_rows, 3, x, y, cx, cy)
    table = shape.table
    table.cell(0, 0).text = "Assets with Inferred Vulnerabilities"
    table.cell(0, 2).text = "Date Observed"
    merge = True
    Table.summary_table(prs, table, num_rows, [0, 2], iv_samp, merge)
    return prs


def init(
    datestring,
    org_name,
    inc,
    creds,
    inc_src_df,
    inc_date_df,
    ce_inc_df,
    domains,
    utld,
    tld_df,
    dm_df,
    dm_samp,
    malware,
    uma,
    ma_act_df,
    ma_samp,
    vulns,
    iv_df,
    iv_act_df,
    iv_samp,
    iv_attach,
    vuln_ma_df,
    vuln_ma_df2,
    assets,
    web,
    dark,
    web_df,
    web_source_df,
    web_attach,
    dark_web_df,
    web_only_df,
    prs,
):
    """Gather data."""
    end_date = datetime.strptime(datestring, "%Y-%m-%d").date()
    if end_date.day == 15:
        start = datetime(end_date.year, end_date.month, 1)
    else:
        start = datetime(end_date.year, end_date.month, 16)
    start = start.strftime("%m/%d/%Y")
    end = end_date.strftime("%m/%d/%Y")
    prs = cover(prs, org_name, start, end)
    prs = overview(
        prs,
        creds,
        domains,
        malware,
        vulns,
        web,
        tld_df,
        inc_src_df,
        web_df,
        ma_act_df,
        iv_act_df,
        dark_web_df,
        web_only_df,
    )
    prs = credential(prs, inc, creds, inc_src_df, inc_date_df, ce_inc_df)
    prs = masquerading(prs, domains, utld, tld_df, dm_df, dm_samp)
    prs = mal_vul(
        prs, ma_act_df, iv_act_df, vuln_ma_df, vuln_ma_df2, vulns, uma, assets
    )
    prs = dark_web(prs, web_df, web_source_df, web, dark, dark_web_df, web_only_df)
    prs = supplimental(prs, ma_samp, dm_samp, iv_samp)
    return prs
