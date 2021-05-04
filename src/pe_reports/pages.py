"""Need to insert docstring here."""
# Third-Party Libraries
import pandas as pd
from pptx.chart.data import CategoryChartData
from pptx.enum.chart import XL_CHART_TYPE
from pptx.util import Inches
from stylesheet import Graph, Paragraph

# Use the folloing fuction to locate "Text Box" element in slide.
# find_shape = Paragraph.shapes_find(prs, slide)


class Pages:
    """Need to insert docstring here."""

    def cover(prs):
        """Need to insert docstring here."""
        slide = prs.slides[0]
        shape = Paragraph.shapes(prs, slide)
        text_frame = Paragraph.text_frame(prs, shape)
        frame = text_frame.paragraphs[0]
        run = frame.add_run()
        df_customer = pd.read_csv("src/pe_reports/data/csv/dhs_customer.csv")
        dates = (
            df_customer.iloc[0]["start_date"] + " to " + df_customer.iloc[0]["end_date"]
        )
        run.text = (
            "Prepared for: "
            + str(df_customer.iloc[0]["name"])
            + "\nReporting period: "
            + str(dates)
        )
        font = run.font
        font = Paragraph.text_style_title(prs, font)
        return prs

    def overview(prs):
        """Need to insert docstring here."""
        slide = prs.slides[1]
        shape = Paragraph.shapes(prs, slide)

        # Overeview Value - Credentials exposed in recent posts
        ov_val_01 = Paragraph.text_frame_ov_val(prs, slide, shape, "TextBox 2")
        frame = ov_val_01.paragraphs[0]
        run = frame.add_run()
        df_creds = pd.read_csv("src/pe_reports/data/csv/dhs_creds.csv")
        run.text = str(int(df_creds.iloc[0]["count"]))
        font = run.font
        font = Paragraph.text_style_ov_val(prs, font)

        # Overeview Value - Suspected domain masquerading alerts
        ov_val_02 = Paragraph.text_frame_ov_val(prs, slide, shape, "TextBox 82")
        frame = ov_val_02.paragraphs[0]
        run = frame.add_run()
        df_domains = pd.read_csv("src/pe_reports/data/csv/dhs_domains.csv")
        run.text = str(int(df_domains.iloc[0]["count"]))
        font = run.font
        font = Paragraph.text_style_ov_val(prs, font)

        # Overeview Value - Active malware associations
        ov_val_03 = Paragraph.text_frame_ov_val(prs, slide, shape, "TextBox 86")
        frame = ov_val_03.paragraphs[0]
        run = frame.add_run()
        df_malware = pd.read_csv("src/pe_reports/data/csv/dhs_malware.csv")
        run.text = str(int(df_malware.iloc[0]["count"]))
        font = run.font
        font = Paragraph.text_style_ov_val(prs, font)

        # Overeview Value - Web and dark web mentions
        ov_val_04 = Paragraph.text_frame_ov_val(prs, slide, shape, "TextBox 87")
        frame = ov_val_04.paragraphs[0]
        run = frame.add_run()
        df_vulns = pd.read_csv("src/pe_reports/data/csv/dhs_vulns.csv")
        run.text = str(int(df_vulns.iloc[0]["count"]))
        font = run.font
        font = Paragraph.text_style_ov_val(prs, font)

        # Overeview Value - Credentials exposed in recent posts
        ov_val_05 = Paragraph.text_frame_ov_val(prs, slide, shape, "TextBox 90")
        frame = ov_val_05.paragraphs[0]
        run = frame.add_run()
        df_web = pd.read_csv("src/pe_reports/data/csv/dhs_web.csv")
        run.text = str(int(df_web.iloc[0]["count"]))
        font = run.font
        font = Paragraph.text_style_ov_val(prs, font)

        # Bar Graph - Top Level Domains used for masquerading
        chart = CategoryChartData()
        tld_df = pd.read_csv("src/pe_reports/data/csv/dhs_tld_df.csv").fillna(0)

        chart.categories = list(tld_df.columns.values)
        chart.add_series("Top Level Domains", list(tld_df.loc[0]))
        x, y, cx, cy = Inches(3.5), Inches(2.9), Inches(2), Inches(1.5)
        chart = slide.shapes.add_chart(
            XL_CHART_TYPE.COLUMN_STACKED, x, y, cx, cy, chart
        ).chart
        chart = Graph.bar_sm(prs, slide, chart)

        # Bar Graph - Sources of credential exposures
        chart = CategoryChartData()
        ce_df = pd.read_csv("src/pe_reports/data/csv/dhs_ce_df.csv").fillna(0)

        chart.categories = list(ce_df.columns.values)
        chart.add_series("Top Level Domains", list(ce_df.loc[0]))
        x, y, cx, cy = Inches(5.75), Inches(2.9), Inches(2), Inches(1.5)
        chart = slide.shapes.add_chart(
            XL_CHART_TYPE.COLUMN_STACKED, x, y, cx, cy, chart
        ).chart
        chart = Graph.bar_sm(prs, slide, chart)

        # Line Graph - Sources of credential exposures
        chart = CategoryChartData()
        web_df = pd.read_csv("src/pe_reports/data/csv/dhs_web_df.csv").fillna(0)

        chart.categories = list(web_df.columns.values)
        chart.add_series("Web", list(web_df.loc[0]))
        chart.add_series("Dark Web", list(web_df.loc[1]))

        x, y, cx, cy = Inches(3.5), Inches(5), Inches(4.8), Inches(2.15)
        chart = slide.shapes.add_chart(XL_CHART_TYPE.LINE, x, y, cx, cy, chart).chart
        chart = Graph.line_med(prs, slide, chart)

        # Bar Graph - Active malware associations
        chart = CategoryChartData()

        ma_df = pd.read_csv("src/pe_reports/data/csv/dhs_ma_df.csv").fillna(0)

        chart.categories = list(ma_df.columns.values)
        chart.add_series("Sources", list(ma_df.loc[0]))

        x, y, cx, cy = Inches(8.25), Inches(2.9), Inches(4.5), Inches(2.0)
        chart = slide.shapes.add_chart(
            XL_CHART_TYPE.COLUMN_STACKED_100, x, y, cx, cy, chart
        ).chart
        chart = Graph.bar_med_100(prs, slide, chart)

        # Bar Graph - inferred vulnerabilities found via external observation
        chart = CategoryChartData()
        iv_df = pd.read_csv("src/pe_reports/data/csv/dhs_iv_df.csv").fillna(0)

        chart.categories = list(iv_df.columns.values)
        chart.add_series("Sources", list(iv_df.loc[0]))

        x, y, cx, cy = Inches(8.25), Inches(4.9), Inches(4.5), Inches(2.0)
        chart = slide.shapes.add_chart(
            XL_CHART_TYPE.COLUMN_STACKED_100, x, y, cx, cy, chart
        ).chart
        chart = Graph.bar_med_100(prs, slide, chart)
        return prs
