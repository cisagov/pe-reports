"""Generate a stakeholders scorecard based on a data dictionary."""
# Standard Python Libraries
import io
import os

# Third-Party Libraries
from PyPDF2 import PdfReader, PdfWriter
import circlify
import matplotlib.pyplot as plt
import numpy as np
import pandas as pd
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import ParagraphStyle
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont
from reportlab.pdfgen import canvas
from reportlab.platypus import Frame, Paragraph, Table, TableStyle

BASE_DIR = os.path.abspath(os.path.dirname(__file__))
IN_FILEPATH = BASE_DIR + "/empty_scorecard.pdf"
ON_PAGE_INDEX = 0
UNDERNEATH = (
    False  # if True, new content will be placed underneath page (painted first)
)

pdfmetrics.registerFont(TTFont("Frank_Goth", BASE_DIR + "/FranklinGothic.ttf"))
pdfmetrics.registerFont(
    TTFont("Frank_Goth_Book", BASE_DIR + "/Franklin_Gothic_Book_Regular.ttf")
)


def build_kpi_string(value, last_value):
    """Build a string to show kpi and change since the last period."""
    if not last_value:
        last_value = 0
    value_diff = value - last_value
    if value_diff > 0:
        string = f" <font size=18> {value}</font><br></br> Increase of {value_diff}"

    elif value_diff < 0:
        string = f" <font size=18> {value}</font><br></br> Decrease of {value_diff}"
    else:
        string = f" <font size=18> {value}</font><br></br> No Change"
    return string


def determine_arrow(value, last_value, color=False):
    """Determine the arrow color and direction based on current and previous values."""
    if not last_value:
        last_value = 0
    value_diff = value - last_value
    if color:
        if value_diff > 0:
            return BASE_DIR + "/up_red.png"
        elif value_diff < 0:
            return BASE_DIR + "/down_green.png"
        else:
            return BASE_DIR + "/no_change.png"
    else:
        if value_diff > 0:
            return BASE_DIR + "/up_black.png"
        elif value_diff < 0:
            return BASE_DIR + "/down_black.png"
        else:
            return BASE_DIR + "/no_change.png"


def create_scorecard(data_dict, file_name):
    """Create a scorecard from a user provided data dictionary."""
    show_Border = False
    packet = io.BytesIO()
    # create a new PDF with Reportlab
    can = canvas.Canvas(packet, pagesize=letter)
    can.setFillColorRGB(0, 0, 0)  # choose your font colour
    can.setFont("Frank_Goth", 20)
    org_name = can.beginText()
    org_name.setTextOrigin(20, 625)

    org_name_style = ParagraphStyle(
        "org_name_style",
        fontName="Frank_Goth",
        fontSize=15,
        textColor="white",
        splitLongWords=1,
    )
    org_name_len = len(data_dict["org_name"])
    # print(org_name_len)
    # Change font size of org name based on how long the string is
    if org_name_len < 26:
        org_name_style.fontSize = 20
        org_name_style.leading = 17
    elif org_name_len < 57:
        org_name_style.fontSize = 13
        org_name_style.leading = 14
    elif org_name_len < 73:
        org_name_style.fontSize = 12
        org_name_style.leading = 11
    else:
        org_name_style.fontSize = 10.5
    org_name_frame = Frame(15, 584, 170, 61, showBoundary=show_Border)
    org_name = Paragraph(data_dict["org_name"], style=org_name_style)
    org_name_frame.addFromList([org_name], can)
    kpi_style = ParagraphStyle(
        "base_style",
        fontName="Frank_Goth",
        fontSize=24,
        textColor="white",
        splitLongWords=1,
        alignment=0,
    )
    cred_kpi_frame = Frame(65, 527, 125, 70, showBoundary=show_Border)
    cred_kpi = Paragraph(
        f"{data_dict['breach_count']} <font size=12> Breaches</font><br></br><br></br> {data_dict['creds_count']} <font size=12>Credentials</font>",
        style=kpi_style,
    )
    cred_kpi_frame.addFromList([cred_kpi], can)

    dns_kpi_frame = Frame(65, 458, 125, 70, showBoundary=show_Border)
    dns_kpi = Paragraph(
        f"{data_dict['domain_alert_count']} <font size=12><br></br>Suspected Domain Masquerading Alerts</font>",
        style=kpi_style,
    )
    dns_kpi_frame.addFromList([dns_kpi], can)

    vuln_kpi_frame = Frame(65, 395, 125, 70, showBoundary=show_Border)
    vuln_kpi = Paragraph(
        f"{data_dict['verified_vuln_count']} <font size=12><br></br>Confirmed Vulnerabilities</font>",
        style=kpi_style,
    )
    vuln_kpi_frame.addFromList([vuln_kpi], can)

    dark_alert_kpi_frame = Frame(65, 327, 125, 70, showBoundary=show_Border)
    dark_alert_kpi = Paragraph(
        f"{data_dict['dark_web_alerts_count']} <font size=12><br></br>Potential Threat Alerts</font>",
        style=kpi_style,
    )
    dark_alert_kpi_frame.addFromList([dark_alert_kpi], can)

    date_style = ParagraphStyle(
        "date_style", fontName="Frank_Goth_Book", fontSize=12, alignment=0
    )

    dates_frame = Frame(213, 625, 300, 50, showBoundary=show_Border)
    date_string = (
        data_dict["start_date"].strftime("%B %d, %Y")
        + " - "
        + data_dict["start_date"].strftime("%B %d, %Y")
    )
    dates_paragraph = Paragraph(f"<font size=13>{date_string}</font>", style=date_style)
    dates_frame.addFromList([dates_paragraph], can)
    img_col1_x = 330
    img_col2_x = 527
    img_size = 22
    ip_address_frame = Frame(210, 573, 180, 50, showBoundary=show_Border)
    ip_address_paragraph = Paragraph(
        f"{build_kpi_string(data_dict['ip_count'], data_dict['last_ip_count'])}",
        style=date_style,
    )
    ip_address_frame.addFromList([ip_address_paragraph], can)
    can.drawImage(
        determine_arrow(data_dict["ip_count"], data_dict["last_ip_count"], False),
        img_col1_x,
        590,
        img_size,
        img_size,
        mask="auto",
    )

    root_domain_frame = Frame(407, 573, 180, 50, showBoundary=show_Border)
    root_domain_paragraph = Paragraph(
        f"{build_kpi_string(data_dict['root_count'], data_dict['last_root_domain_count'])}",
        style=date_style,
    )
    root_domain_frame.addFromList([root_domain_paragraph], can)
    can.drawImage(
        determine_arrow(
            data_dict["root_count"], data_dict["last_root_domain_count"], False
        ),
        img_col2_x,
        590,
        img_size,
        img_size,
        mask="auto",
    )

    sub_domain_frame = Frame(210, 504, 180, 50, showBoundary=show_Border)
    sub_domain_paragraph = Paragraph(
        f"{build_kpi_string(data_dict['sub_count'], data_dict['last_sub_domain_count'])}",
        style=date_style,
    )
    sub_domain_frame.addFromList([sub_domain_paragraph], can)
    can.drawImage(
        determine_arrow(
            data_dict["sub_count"], data_dict["last_sub_domain_count"], False
        ),
        img_col1_x,
        518,
        img_size,
        img_size,
        mask="auto",
    )

    cred_pass_frame = Frame(407, 504, 180, 50, showBoundary=show_Border)
    cred_pass_paragraph = Paragraph(
        f"{build_kpi_string(data_dict['cred_password_count'], data_dict['last_cred_password_count'])}",
        style=date_style,
    )
    cred_pass_frame.addFromList([cred_pass_paragraph], can)
    can.drawImage(
        determine_arrow(
            data_dict["cred_password_count"],
            data_dict["last_cred_password_count"],
            True,
        ),
        img_col2_x,
        518,
        img_size,
        img_size,
        mask="auto",
    )

    sus_vuln_addrs_frame = Frame(210, 432, 180, 50, showBoundary=show_Border)
    sus_vuln_addrs_paragraph = Paragraph(
        f"{build_kpi_string(data_dict['suspected_vuln_addrs_count'], data_dict['last_sus_vuln_addrs_count'])}",
        style=date_style,
    )
    sus_vuln_addrs_frame.addFromList([sus_vuln_addrs_paragraph], can)
    can.drawImage(
        determine_arrow(
            data_dict["suspected_vuln_addrs_count"],
            data_dict["last_sus_vuln_addrs_count"],
            True,
        ),
        img_col1_x,
        448,
        img_size,
        img_size,
        mask="auto",
    )

    sus_vuln_frame = Frame(407, 432, 180, 50, showBoundary=show_Border)
    sus_vuln_paragraph = Paragraph(
        f"{build_kpi_string(data_dict['suspected_vuln_count'], data_dict['last_suspected_vuln_count'])}",
        style=date_style,
    )
    sus_vuln_frame.addFromList([sus_vuln_paragraph], can)
    can.drawImage(
        determine_arrow(
            data_dict["suspected_vuln_count"],
            data_dict["last_suspected_vuln_count"],
            True,
        ),
        img_col2_x,
        448,
        img_size,
        img_size,
        mask="auto",
    )

    ports_frame = Frame(210, 362, 180, 50, showBoundary=show_Border)
    ports_paragraph = Paragraph(
        f"{build_kpi_string(data_dict['insecure_port_count'], data_dict['last_insecure_port_count'])}",
        style=date_style,
    )
    ports_frame.addFromList([ports_paragraph], can)
    can.drawImage(
        determine_arrow(
            data_dict["insecure_port_count"],
            data_dict["last_insecure_port_count"],
            True,
        ),
        img_col1_x,
        377,
        img_size,
        img_size,
        mask="auto",
    )

    actor_activity_frame = Frame(407, 362, 180, 50, showBoundary=show_Border)
    actor_activity_paragraph = Paragraph(
        f"{build_kpi_string(data_dict['threat_actor_count'], data_dict['last_actor_activity_count'])}",
        style=date_style,
    )
    actor_activity_frame.addFromList([actor_activity_paragraph], can)
    can.drawImage(
        determine_arrow(
            data_dict["threat_actor_count"],
            data_dict["last_actor_activity_count"],
            True,
        ),
        img_col2_x,
        377,
        img_size,
        img_size,
        mask="auto",
    )
    if isinstance(data_dict["circles_df"], pd.DataFrame):
        generate_circle_chart(data_dict["circles_df"], "circle_line.png")
        can.drawImage(
            BASE_DIR + "/scorecard_assets/circle_line.png", 0, 18, 255, 255, mask="auto"
        )
    dns_df = data_dict["dns"]
    if len(dns_df) > 0:
        dns_df = dns_df.sort_values(by="count", ascending=False)
        dns_df1 = dns_df.iloc[::2]
        dns_df2 = dns_df.iloc[1::2]

        dns_activity_frame1 = Frame(237, 20, 85, 250, showBoundary=show_Border)
        # dns_activity_paragraph = Paragraph(f"{data_dict['dns']}", style=date_style)

        dns_table1 = Table(
            np.array(dns_df1).tolist(),
            colWidths=None,
            rowHeights=None,
            style=None,
            splitByRow=1,
            repeatRows=0,
            repeatCols=0,
            rowSplitRange=None,
            spaceBefore=None,
            spaceAfter=None,
            cornerRadii=None,
        )
        dns_table1.setStyle(
            TableStyle(
                [
                    ("FONTNAME", (0, 0), (-1, -1), "Frank_Goth_Book"),
                    # ('GRID',(0,0),(-1,-1),0.5,colors.black),
                ]
            )
        )
        dns_table1.hAlign = "LEFT"
        dns_activity_frame1.addFromList([dns_table1], can)
        if len(dns_df2) > 0:
            dns_activity_frame2 = Frame(335, 20, 85, 250, showBoundary=show_Border)
            # dns_activity_paragraph = Paragraph(f"{data_dict['dns']}", style=date_style)
            dns_table2 = Table(
                np.array(dns_df2).tolist(),
                colWidths=None,
                rowHeights=None,
                style=None,
                splitByRow=1,
                repeatRows=0,
                repeatCols=0,
                rowSplitRange=None,
                spaceBefore=None,
                spaceAfter=None,
                cornerRadii=None,
            )
            dns_table2.setStyle(
                TableStyle(
                    [
                        ("FONTNAME", (0, 0), (-1, -1), "Frank_Goth_Book"),
                        # ('GRID',(0,0),(-1,-1),0.5,colors.black),
                    ]
                )
            )
            dns_table2.hAlign = "RIGHT"
            dns_activity_frame2.addFromList([dns_table2], can)

    score_style = ParagraphStyle(
        "score_style",
        fontName="Frank_Goth_Book",
        fontSize=45,
        textColor="#C9C9C9",
        leading=47,
        alignment=0,
    )

    score_frame = Frame(430, 70, 180, 200, showBoundary=show_Border)
    score_paragraph = Paragraph(
        f"{data_dict['pe_number_score']}<br></br>{data_dict['pe_letter_grade']}",
        style=score_style,
    )
    score_frame.addFromList([score_paragraph], can)
    can.save()

    # move to the beginning of the StringIO buffer
    packet.seek(0)
    new_pdf = PdfReader(packet)
    # read your existing PDF
    existing_pdf = PdfReader(open(BASE_DIR + "/empty_scorecard.pdf", "rb"))
    output = PdfWriter()
    # add the "watermark" (which is the new pdf) on the existing page
    page = existing_pdf.pages[0]
    page2 = new_pdf.pages[0]
    page.merge_page(page2)
    output.add_page(page)
    # finally, write "output" to a real file
    outputStream = open(file_name, "wb")
    output.write(outputStream)
    outputStream.close()


def generate_circle_chart(df, name):
    """Create the circle chart based on a pandas dataframe."""
    df = df.sort_values(by="Value", ascending=True)
    # print(df.head())

    circles = circlify.circlify(
        df["Value"].tolist(),
        show_enclosure=True,
        target_enclosure=circlify.Circle(x=0, y=0, r=1),
    )
    # print(circles)

    fig, ax = plt.subplots(figsize=(10, 10))
    ax.axis("off")

    lim = max(
        max(
            abs(circle.x) + circle.r,
            abs(circle.y) + circle.r,
        )
        for circle in circles
    )

    plt.xlim(-lim, lim)
    plt.ylim(-lim, lim)
    # list of labels
    values = df["Value"]
    labels = df["Name"]
    colors = ["#F05A2C", "#953512", "#5E9632", "#0078AE", "#0078AE"]

    for circle, value, label, color_code in zip(circles, values, labels, colors):
        x, y, r = circle
        ax.add_patch(
            plt.Circle((y, x), r * 0.9, alpha=0.6, linewidth=1, color=color_code)
        )
        plt.annotate(
            value, (y, x + 0.05), va="center", ha="center", color="black", fontsize=20
        )
        plt.annotate(
            label, (y, x - 0.02), va="center", ha="center", color="black", fontsize=8
        )

    plt.savefig(
        BASE_DIR + "/scorecard_assets/" + name,
        transparent=False,
        dpi=500,
        bbox_inches="tight",
    )
    plt.clf()
