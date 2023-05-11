"""Generate a unified scorecard for an organization based on a provided data dict."""

# Standard Python Libraries
# import io
import os

# Third-Party Libraries
# from reportlab.lib import utils
from reportlab.lib.colors import HexColor
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import ParagraphStyle
from reportlab.lib.units import inch
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont
from reportlab.pdfgen import canvas
from reportlab.platypus import Frame, Image, Paragraph, Table, TableStyle

BASE_DIR = os.path.abspath(os.path.dirname(__file__))

pdfmetrics.registerFont(
    TTFont("Franklin_Gothic_Book", BASE_DIR + "/fonts/FranklinGothicBook.ttf")
)

pdfmetrics.registerFont(
    TTFont(
        "Franklin_Gothic_Medium_Regular",
        BASE_DIR + "/fonts/FranklinGothicMediumRegular.ttf",
    )
)

defaultPageSize = letter
PAGE_HEIGHT = defaultPageSize[1]
PAGE_WIDTH = defaultPageSize[0]


def determine_arrow(value, last_value, color=False, up_is_good=False):
    """Determine the arrow color and direction based on current and previous values."""
    if not last_value:
        return BASE_DIR + "/scorecard_assets/no_change.png"
    if not value:
        return BASE_DIR + "/scorecard_assets/no_change.png"
    print(value)
    print(last_value)
    value_diff = value - last_value
    if color:
        if value_diff > 0:
            if up_is_good:
                return BASE_DIR + "/scorecard_assets/up_green.png"
            else:
                return BASE_DIR + "/scorecard_assets/up_red.png"
        elif value_diff < 0:
            if up_is_good:
                return BASE_DIR + "/scorecard_assets/down_red.png"
            else:
                return BASE_DIR + "/scorecard_assets/down_green.png"
        else:
            return BASE_DIR + "/scorecard_assets/no_change.png"
    else:
        if value_diff > 0:
            return BASE_DIR + "/scorecard_assets/up_black.png"
        elif value_diff < 0:
            return BASE_DIR + "/scorecard_assets/down_black.png"
        else:
            return BASE_DIR + "/scorecard_assets/no_change.png"


def format_table(data, column_widths, half_page=False, trending=True):
    """Read in data and convert it to a table and format it with a provided style list."""
    table = Table(
        data,
        colWidths=column_widths,
        rowHeights=30,
        style=None,
        splitByRow=1,
        repeatRows=1,
        repeatCols=0,
        rowSplitRange=None,
        spaceBefore=None,
        spaceAfter=None,
        cornerRadii=None,
    )

    style_settings = [
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("ALIGN", (1, 0), (-1, -1), "CENTER"),
        ("ALIGN", (0, 0), (0, -1), "LEFT"),
        ("LEFTPADDING", (0, 0), (0, -1), 20),
        # ("INNERGRID", (0, 0), (-1, -1), 1, "white"),
        ("FONT", (0, 0), (-1, 0), "Franklin_Gothic_Medium_Regular"),
        ("FONT", (0, 1), (0, -1), "Franklin_Gothic_Medium_Regular"),
        ("FONT", (1, 1), (-1, -1), "Franklin_Gothic_Book"),
        ("FONTSIZE", (0, 0), (-1, -1), 16),
        (
            "ROWBACKGROUNDS",
            (0, 0),
            (-1, -1),
            [HexColor("#FFFFFF"), HexColor("#DEEBF7")],
        ),
        ("LINEBELOW", (0, -1), (-1, -1), 1.5, HexColor("#005287")),
        ("LINEABOVE", (0, 0), (-1, 1), 1.5, HexColor("#005287")),
    ]
    if half_page and trending:
        style_settings.append(("LEFTPADDING", (0, 0), (0, -1), 6))
    else:
        style_settings.append(("LEFTPADDING", (0, 0), (0, -1), 20))

    table.setStyle(TableStyle(style_settings))

    return table


def create_scorecard(
    data_dict, file_name, include_trending=True, include_scores=True, exclude_bods=False
):
    """Generate a unified scorecard based on a passed in data_dict."""
    # create a new PDF with Reportlab
    can = canvas.Canvas(file_name, pagesize=letter)
    # can.drawString(100,700, "First Time Using reportlab")
    can.setTitle(
        "External Attack Surface Evaluation prepared for "
        + data_dict["agency_id"]
        + " for "
        + data_dict["date"]
    )
    can.setSubject("Attack Surface")
    can.setAuthor("CISA CyHy")
    can.setCreator("P&E Team")
    can.setKeywords(["ASM"])
    can.setFillColor(HexColor("#003e67"))
    can.setStrokeColor("#1d5288")

    # can.rect(0, PAGE_HEIGHT - 1.25*inch, 8.5 * inch, 1.25 * inch, fill=1)
    # ADD Static graphics
    # **** Generate Header *****

    can.drawImage(
        BASE_DIR + "/scorecard_assets/Header.png",
        0,
        PAGE_HEIGHT - 1.25 * inch,
        width=PAGE_WIDTH,
        height=1.25 * inch,
        mask="auto",
    )
    title_style = ParagraphStyle(
        "Title_style",
        fontName="Franklin_Gothic_Book",
        fontSize=34,
        textColor="white",
        leading=36,
    )
    score_style = ParagraphStyle(
        "score_style",
        fontName="Franklin_Gothic_Medium_Regular",
        fontSize=32,
        textColor="white",
        alignment=2,
    )
    if include_scores:
        can.drawImage(
            BASE_DIR + "/scorecard_assets/cisa.png",
            0.25 * inch,
            PAGE_HEIGHT - 1.1 * inch,
            width=65,
            height=65,
            mask="auto",
        )
        title_frame = Frame(100, 707, 380, 85)
        overall_score_style = ParagraphStyle(
            "overall_score_style",
            fontName="Franklin_Gothic_Book",
            fontSize=65,
            textColor="white",
            alignment=1,
        )
        overall_score_frame = Frame(
            7 * inch, PAGE_HEIGHT - 0.95 * inch, width=90, height=70, showBoundary=False
        )
        overall_score_frame.addFromList(
            [Paragraph(data_dict["overall_score"], overall_score_style)], can
        )
    else:
        can.drawImage(
            BASE_DIR + "/scorecard_assets/cisa.png",
            7.2 * inch,
            PAGE_HEIGHT - 1.1 * inch,
            width=65,
            height=65,
            mask="auto",
        )
        title_frame = Frame(0.3 * inch, 707, 380, 85)

    title_frame.addFromList(
        [Paragraph("External Attack Surface Evaluation", style=title_style)],
        can,
    )

    agency_style = ParagraphStyle(
        "Agency_style",
        fontName="Franklin_Gothic_Medium_Regular",
        fontSize=20,
        textColor="black",
        leading=20,
    )
    agency_frame = Frame(0.25 * inch, 657, 8 * inch, 0.6 * inch, showBoundary=False)
    name = data_dict["agency_name"]
    if len(name) > 48:
        name = data_dict["agency_id"]
    agency_frame.addFromList(
        [Paragraph(name + " - " + data_dict["date"], style=agency_style)],
        can,
    )
    can.setLineWidth(1.5)
    can.setStrokeColor("black")
    can.line(0.25 * inch, 665, 7 * inch, 665)

    divider_style = ParagraphStyle(
        "divider_style",
        fontName="Franklin_Gothic_Medium_Regular",
        fontSize=18,
        textColor="white",
    )
    header_style = ParagraphStyle(
        "header_style",
        fontName="Franklin_Gothic_Medium_Regular",
        fontSize=18,
        textColor="#5D9741",
        leading=18,
        alignment=1,
    )
    databox_style_left = ParagraphStyle(
        "databox_style",
        fontName="Franklin_Gothic_Book",
        fontSize=18,
        textColor="white",
        leading=17,
    )
    databox_style_right = ParagraphStyle(
        "databox_style",
        fontName="Franklin_Gothic_Book",
        fontSize=18,
        textColor="white",
        leading=17,
        alignment=2,
    )
    databox_style_center = ParagraphStyle(
        "databox_style",
        fontName="Franklin_Gothic_Book",
        fontSize=15,
        textColor="black",
        leading=17,
        alignment=1,
    )
    # **** Generate Section Dividers *****
    y_value = 8.7 * inch
    can.drawImage(
        BASE_DIR + "/scorecard_assets/section_divider.png",
        0,
        y_value,
        width=7.05 * inch,
        height=0.42 * inch,
        mask="auto",
    )
    discovery_frame = Frame(
        0.5 * inch, y_value + 0.04 * inch, 3 * inch, 0.42 * inch, showBoundary=False
    )
    discovery_frame.addFromList([Paragraph("DISCOVERY", style=divider_style)], can)

    data_sent_style = ParagraphStyle(
        "data_sent_style",
        fontName="Franklin_Gothic_Medium_Regular",
        fontSize=16,
    )
    data_sent_frame = Frame(
        0.25 * inch, y_value - 0.55 * inch, 8 * inch, 0.6 * inch, showBoundary=False
    )
    data_sent_frame.addFromList(
        [
            Paragraph(
                "Date stakeholder last updated assets: "
                + data_dict["last_data_sent_date"],
                style=data_sent_style,
            )
        ],
        can,
    )

    if include_scores:
        discover_score_frame = Frame(
            5.5 * inch if include_trending else 6 * inch,
            y_value - 0.01 * inch,
            0.8 * inch,
            0.6 * inch,
            showBoundary=False,
        )
        discover_score_frame.addFromList(
            [Paragraph(data_dict["discovery_score"], style=score_style)], can
        )
        if include_trending:
            if data_dict["discovery_trend_dir"] == -1:
                can.drawImage(
                    BASE_DIR + "/scorecard_assets/red_score_arrow.png",
                    6.3 * inch,
                    y_value + 0.06 * inch,
                    width=0.34 * inch,
                    height=0.3 * inch,
                    mask="auto",
                )
            elif data_dict["discovery_trend_dir"] == 1:
                can.drawImage(
                    BASE_DIR + "/scorecard_assets/green_score_arrow.png",
                    6.3 * inch,
                    y_value + 0.06 * inch,
                    width=0.34 * inch,
                    height=0.3 * inch,
                    mask="auto",
                )
            else:
                can.drawImage(
                    BASE_DIR + "/scorecard_assets/grey_dot.png",
                    6.35 * inch,
                    y_value + 0.1 * inch,
                    width=0.15 * inch,
                    height=0.15 * inch,
                    mask="auto",
                )

    box_width = 3.85 * inch
    box_height = 1.55 * inch
    col1_x_value = 0.3 * inch
    row1_y_value = 6.7 * inch
    col2_x_value = PAGE_WIDTH - box_width - col1_x_value
    row2_y_value = 4.9 * inch
    # **** Generate IP Addresses Boxes ******
    can.drawImage(
        BASE_DIR + "/scorecard_assets/data_box.png",
        col1_x_value,
        row1_y_value,
        width=box_width,
        height=box_height,
        mask="auto",
    )
    ip_header_frame = Frame(
        col1_x_value,
        row1_y_value + 1.3 * inch,
        box_width,
        0.42 * inch,
        showBoundary=False,
    )
    ip_header_frame.addFromList([Paragraph("IP Addresses", style=header_style)], can)

    ip_reported_frame = Frame(
        col1_x_value + 2,
        row1_y_value + 0.54 * inch,
        box_width / 2,
        0.7 * inch,
        showBoundary=False,
    )
    ip_reported_frame.addFromList(
        [
            Paragraph(
                f'{data_dict["ips_self_reported"]:,}'
                + "<br/><font size='14'> Self Reported</font>",
                style=databox_style_left,
            )
        ],
        can,
    )

    ip_discovered_frame = Frame(
        col1_x_value + box_width / 2 - 2,
        row1_y_value + 0.54 * inch,
        box_width / 2,
        0.7 * inch,
        showBoundary=False,
    )
    ip_discovered_frame.addFromList(
        [
            Paragraph(
                f'{data_dict["ips_discovered"]:,}'
                + "<br/><font size='14'> Discovered</font>",
                style=databox_style_right,
            )
        ],
        can,
    )

    ip_monitored_frame = Frame(
        col1_x_value, row1_y_value, box_width, 0.48 * inch, showBoundary=False
    )
    if not data_dict["ips_monitored"]:
        ip_monitored_frame.addFromList(
            [Paragraph("Zero Monitored", style=databox_style_center)], can
        )
    else:
        ip_monitored_frame.addFromList(
            [
                Paragraph(
                    f'{data_dict["ips_monitored"]:,}' + " Monitored",
                    style=databox_style_center,
                )
            ],
            can,
        )

    if include_trending:
        trend_image = determine_arrow(
            data_dict["ips_monitored"],
            data_dict["ips_monitored_trend"],
        )
        can.drawImage(
            trend_image,
            col1_x_value + 0.5 * inch,
            row1_y_value + 0.13 * inch,
            width=22,
            height=22,
            mask="auto",
        )
    # **** Generate Domains Boxes ******
    can.drawImage(
        BASE_DIR + "/scorecard_assets/data_box.png",
        col2_x_value,
        row1_y_value,
        width=box_width,
        height=box_height,
        mask="auto",
    )
    domains_header_frame = Frame(
        col2_x_value,
        row1_y_value + 1.3 * inch,
        box_width,
        0.42 * inch,
        showBoundary=False,
    )
    domains_header_frame.addFromList([Paragraph("Domains", style=header_style)], can)

    domain_reported_frame = Frame(
        col2_x_value + 2,
        row1_y_value + 0.54 * inch,
        box_width / 2,
        0.7 * inch,
        showBoundary=False,
    )
    domain_reported_frame.addFromList(
        [
            Paragraph(
                f'{data_dict["domains_self_reported"]:,}'
                + "<br/><font size='14'> Self Reported</font>",
                style=databox_style_left,
            )
        ],
        can,
    )

    domain_discovered_frame = Frame(
        col2_x_value + box_width / 2 - 2,
        row1_y_value + 0.54 * inch,
        box_width / 2,
        0.7 * inch,
        showBoundary=False,
    )
    domain_discovered_frame.addFromList(
        [
            Paragraph(
                f'{data_dict["domains_discovered"]:,}'
                + "<br/><font size='14'> Discovered</font>",
                style=databox_style_right,
            )
        ],
        can,
    )

    domain_monitored_frame = Frame(
        col2_x_value, row1_y_value, box_width, 0.48 * inch, showBoundary=False
    )
    if not data_dict["domains_monitored"]:
        domain_monitored_frame.addFromList(
            [Paragraph("Zero Monitored", style=databox_style_center)], can
        )
    else:
        domain_monitored_frame.addFromList(
            [
                Paragraph(
                    f'{data_dict["domains_monitored"]:,}' + " Monitored",
                    style=databox_style_center,
                )
            ],
            can,
        )

    if include_trending:
        trend_image = determine_arrow(
            data_dict["domains_monitored"],
            data_dict["domains_monitored_trend"],
        )
        can.drawImage(
            trend_image,
            col2_x_value + 0.5 * inch,
            row1_y_value + 0.13 * inch,
            width=22,
            height=22,
            mask="auto",
        )
    # **** Generate Web Apps Boxes ******
    can.drawImage(
        BASE_DIR + "/scorecard_assets/data_box.png",
        col1_x_value,
        row2_y_value,
        width=box_width,
        height=box_height,
        mask="auto",
    )
    web_app_header_frame = Frame(
        col1_x_value,
        row2_y_value + 1.3 * inch,
        box_width,
        0.42 * inch,
        showBoundary=False,
    )
    web_app_header_frame.addFromList(
        [Paragraph("Web Applications", style=header_style)], can
    )

    web_app_reported_frame = Frame(
        col1_x_value + 2,
        row2_y_value + 0.54 * inch,
        box_width / 2,
        0.7 * inch,
        showBoundary=False,
    )
    web_app_reported_frame.addFromList(
        [
            Paragraph(
                f'{data_dict["web_apps_self_reported"]:,}'
                + "<br/><font size='14'> Self Reported</font>",
                style=databox_style_left,
            )
        ],
        can,
    )

    web_app_discovered_frame = Frame(
        col1_x_value + box_width / 2 - 2,
        row2_y_value + 0.54 * inch,
        box_width / 2,
        0.7 * inch,
        showBoundary=False,
    )
    web_app_discovered_frame.addFromList(
        [
            Paragraph(
                f'{data_dict["web_apps_discovered"]:,}'
                + "<br/><font size='14'> Discovered</font>",
                style=databox_style_right,
            )
        ],
        can,
    )

    web_app_monitored_frame = Frame(
        col1_x_value, row2_y_value, box_width, 0.48 * inch, showBoundary=False
    )
    if not data_dict["web_apps_monitored"]:
        web_app_monitored_frame.addFromList(
            [Paragraph("Zero Monitored", style=databox_style_center)], can
        )
    else:
        web_app_monitored_frame.addFromList(
            [
                Paragraph(
                    f'{data_dict["web_apps_monitored"]:,}' + " Monitored",
                    style=databox_style_center,
                )
            ],
            can,
        )

    if include_trending:
        trend_image = determine_arrow(
            data_dict["web_apps_monitored"],
            data_dict["web_apps_monitored_trend"],
        )
        can.drawImage(
            trend_image,
            col1_x_value + 0.5 * inch,
            row2_y_value + 0.13 * inch,
            width=22,
            height=22,
            mask="auto",
        )
    # **** Generate Certificates Boxes ******
    can.drawImage(
        BASE_DIR + "/scorecard_assets/data_box.png",
        col2_x_value,
        row2_y_value,
        width=box_width,
        height=box_height,
        mask="auto",
    )
    certs_header_frame = Frame(
        col2_x_value,
        row2_y_value + 1.3 * inch,
        box_width,
        0.42 * inch,
        showBoundary=False,
    )
    certs_header_frame.addFromList(
        [Paragraph("Certificates (ED 19-01)", style=header_style)], can
    )

    certs_reported_frame = Frame(
        col2_x_value + 2,
        row2_y_value + 0.54 * inch,
        box_width / 2,
        0.7 * inch,
        showBoundary=False,
    )
    certs_reported_frame.addFromList(
        [
            Paragraph(
                f'{data_dict["certs_self_reported"]:,}'
                + "<br/><font size='14'> Self Reported</font>",
                style=databox_style_left,
            )
        ],
        can,
    )

    certs_discovered_frame = Frame(
        col2_x_value + box_width / 2 - 2,
        row2_y_value + 0.54 * inch,
        box_width / 2,
        0.7 * inch,
        showBoundary=False,
    )
    certs_discovered_frame.addFromList(
        [
            Paragraph(
                f'{data_dict["certs_discovered"]:,}'
                + "<br/><font size='14'> Discovered</font>",
                style=databox_style_right,
            )
        ],
        can,
    )

    certs_monitored_frame = Frame(
        col2_x_value, row2_y_value, box_width, 0.48 * inch, showBoundary=False
    )
    if not data_dict["certs_monitored"]:
        certs_monitored_frame.addFromList(
            [Paragraph("Zero Monitored", style=databox_style_center)], can
        )
    else:
        certs_monitored_frame.addFromList(
            [
                Paragraph(
                    f'{data_dict["certs_monitored"]:,}' + " Monitored",
                    style=databox_style_center,
                )
            ],
            can,
        )

    if include_trending:
        trend_image = determine_arrow(
            data_dict["certs_monitored"],
            data_dict["certs_monitored_trend"],
        )
        can.drawImage(
            trend_image,
            col2_x_value + 0.5 * inch,
            row2_y_value + 0.13 * inch,
            width=22,
            height=22,
            mask="auto",
        )
    # **** Generate Profiling Divider *****
    y_value = 4.3 * inch
    can.drawImage(
        BASE_DIR + "/scorecard_assets/section_divider.png",
        0,
        y_value,
        width=7.05 * inch,
        height=0.42 * inch,
        mask="auto",
    )
    profiling_frame = Frame(
        0.5 * inch, y_value + 0.04 * inch, 3 * inch, 0.42 * inch, showBoundary=False
    )
    profiling_frame.addFromList([Paragraph("PROFILING", style=divider_style)], can)
    if include_scores:
        profiling_score_frame = Frame(
            5.5 * inch if include_trending else 6 * inch,
            y_value - 0.01 * inch,
            0.8 * inch,
            0.6 * inch,
            showBoundary=False,
        )
        profiling_score_frame.addFromList(
            [Paragraph(data_dict["profiling_score"], style=score_style)], can
        )
        if include_trending:
            if data_dict["profiling_trend_dir"] == -1:
                can.drawImage(
                    BASE_DIR + "/scorecard_assets/red_score_arrow.png",
                    6.3 * inch,
                    y_value + 0.06 * inch,
                    width=0.34 * inch,
                    height=0.3 * inch,
                    mask="auto",
                )
            elif data_dict["profiling_trend_dir"] == 1:
                can.drawImage(
                    BASE_DIR + "/scorecard_assets/green_score_arrow.png",
                    6.3 * inch,
                    y_value + 0.06 * inch,
                    width=0.34 * inch,
                    height=0.3 * inch,
                    mask="auto",
                )
            else:
                can.drawImage(
                    BASE_DIR + "/scorecard_assets/grey_dot.png",
                    6.35 * inch,
                    y_value + 0.1 * inch,
                    width=0.15 * inch,
                    height=0.15 * inch,
                    mask="auto",
                )
    y_value = 2.35 * inch
    # *** Ports Table ****
    ports_header_frame = Frame(
        col1_x_value, y_value + 1.48 * inch, box_width, 0.42 * inch, showBoundary=False
    )
    ports_header_frame.addFromList([Paragraph("Ports", style=header_style)], can)
    if include_trending:
        ports_data = [
            ["", "Count", "", "Trending"],
            [
                "Total",
                data_dict["ports_total_count"],
                Image(
                    determine_arrow(
                        data_dict["ports_total_count"], data_dict["ports_total_trend"]
                    ),
                    20,
                    20,
                ),
                abs(data_dict["ports_total_count"] - data_dict["ports_total_trend"]),
            ],
            [
                "Risky",
                data_dict["ports_risky_count"],
                Image(
                    determine_arrow(
                        data_dict["ports_risky_count"],
                        data_dict["ports_risky_trend"],
                        color=True,
                    ),
                    20,
                    20,
                ),
                abs(data_dict["ports_risky_count"] - data_dict["ports_risky_trend"]),
            ],
        ]
        col_widths = [1 * inch, 1.35 * inch, 0.2 * inch, 1.3 * inch]
        ports_table = format_table(
            ports_data,
            col_widths,
            half_page=True,
        )
    else:
        ports_data = [
            ["", "Count"],
            ["Total", data_dict["ports_total_count"]],
            ["Risky", data_dict["ports_risky_count"]],
        ]
        col_widths = [2 * inch, 1.85 * inch]
        ports_table = format_table(
            ports_data, col_widths, half_page=True, trending=False
        )

    ports_table_frame = Frame(
        0.3 * inch, y_value, 3.85 * inch, 1.5 * inch, showBoundary=False
    )
    ports_table_frame.addFromList([ports_table], can)

    # *** Protocols Table ****
    ports_header_frame = Frame(
        col2_x_value, y_value + 1.48 * inch, box_width, 0.42 * inch, showBoundary=False
    )
    ports_header_frame.addFromList([Paragraph("Protocols", style=header_style)], can)
    if include_trending:
        protocol_data = [
            ["", "Count", "", "Trending"],
            [
                "Total",
                data_dict["protocol_total_count"],
                Image(
                    determine_arrow(
                        data_dict["protocol_total_count"],
                        data_dict["protocol_total_trend"],
                    ),
                    20,
                    20,
                ),
                abs(
                    data_dict["protocol_total_count"]
                    - data_dict["protocol_total_trend"]
                ),
            ],
            [
                "Insecure",
                data_dict["protocol_insecure_count"],
                Image(
                    determine_arrow(
                        data_dict["protocol_insecure_count"],
                        data_dict["protocol_insecure_trend"],
                        color=True,
                    ),
                    20,
                    20,
                ),
                abs(
                    data_dict["protocol_insecure_count"]
                    - data_dict["protocol_insecure_trend"]
                ),
            ],
        ]
        col_widths = [1 * inch, 1.35 * inch, 0.2 * inch, 1.3 * inch]
        protocol_table = format_table(
            protocol_data,
            col_widths,
            half_page=True,
        )
    else:
        protocol_data = [
            ["", "Count"],
            ["Total", data_dict["protocol_total_count"]],
            ["Insecure", data_dict["protocol_insecure_count"]],
        ]
        col_widths = [2 * inch, 1.85 * inch]
        protocol_table = format_table(
            protocol_data, col_widths, half_page=True, trending=False
        )

    protocol_table_frame = Frame(
        col2_x_value, y_value, 3.85 * inch, 1.5 * inch, showBoundary=False
    )
    protocol_table_frame.addFromList([protocol_table], can)

    y_value = 0.5 * inch
    # *** Services Table ****
    services_header_frame = Frame(
        col1_x_value, y_value + 1.48 * inch, box_width, 0.42 * inch, showBoundary=False
    )
    services_header_frame.addFromList([Paragraph("Services", style=header_style)], can)

    if include_trending:
        services_data = [
            ["", "Count", "", "Trending"],
            [
                "Total",
                data_dict["services_total_count"],
                Image(
                    determine_arrow(
                        data_dict["services_total_count"],
                        data_dict["services_total_trend"],
                        color=True,
                    ),
                    20,
                    20,
                ),
                abs(
                    data_dict["services_total_count"]
                    - data_dict["services_total_trend"]
                ),
            ],
        ]
        col_widths = [1.5 * inch, 1 * inch, 0.2 * inch, 1.15 * inch]
        services_table = format_table(services_data, col_widths, half_page=True)
    else:
        services_data = [["", "Count"], ["Total", data_dict["services_total_count"]]]
        col_widths = [2 * inch, 1.85 * inch]
        services_table = format_table(
            services_data, col_widths, half_page=True, trending=False
        )

    services_table_frame = Frame(
        0.3 * inch, y_value, 3.85 * inch, 1.5 * inch, showBoundary=False
    )
    services_table_frame.addFromList([services_table], can)

    # *** Software Table ****
    software_header_frame = Frame(
        col2_x_value, y_value + 1.48 * inch, box_width, 0.42 * inch, showBoundary=False
    )
    software_header_frame.addFromList([Paragraph("Software", style=header_style)], can)
    if include_trending:
        software_data = [
            ["", "Count", "", "Trending"],
            [
                "Unsupported",
                data_dict["software_unsupported_count"],
                Image(
                    determine_arrow(
                        data_dict["software_unsupported_count"],
                        data_dict["software_unsupported_trend"],
                        color=True,
                    ),
                    20,
                    20,
                ),
                abs(
                    data_dict["software_unsupported_count"]
                    - data_dict["software_unsupported_trend"]
                ),
            ],
        ]
        col_widths = [1.5 * inch, 1 * inch, 0.2 * inch, 1.15 * inch]
        software_table = format_table(software_data, col_widths, half_page=True)
    else:
        software_data = [
            ["", "Count"],
            ["Unsupported", data_dict["software_unsupported_count"]],
        ]
        col_widths = [2 * inch, 1.85 * inch]
        software_table = format_table(
            software_data, col_widths, half_page=True, trending=False
        )

    software_table_frame = Frame(
        col2_x_value, y_value, 3.85 * inch, 1.5 * inch, showBoundary=False
    )
    software_table_frame.addFromList([software_table], can)

    # **** Generate Footer Banner *****
    can.drawImage(
        BASE_DIR + "/scorecard_assets/footer_banner.png",
        0,
        0,
        width=PAGE_WIDTH,
        height=0.8 * inch,
        mask="auto",
    )

    can.drawImage(
        BASE_DIR + "/scorecard_assets/cisa.png",
        PAGE_WIDTH - 1.1 * inch,
        0.1 * inch,
        width=45,
        height=45,
        mask="auto",
    )

    # **** Generate new page ****
    can.showPage()
    # *** Generate Identification Divider ****
    y_value = 10.3 * inch
    can.drawImage(
        BASE_DIR + "/scorecard_assets/section_divider.png",
        0,
        y_value,
        width=7.05 * inch,
        height=0.42 * inch,
        mask="auto",
    )
    identification_frame = Frame(
        0.5 * inch, y_value + 0.04 * inch, 3 * inch, 0.42 * inch, showBoundary=False
    )
    identification_frame.addFromList(
        [Paragraph("IDENTIFICATION", style=divider_style)], can
    )
    if include_scores:
        identification_score_frame = Frame(
            5.5 * inch if include_trending else 6 * inch,
            y_value - 0.01 * inch,
            0.8 * inch,
            0.6 * inch,
            showBoundary=False,
        )
        identification_score_frame.addFromList(
            [Paragraph(data_dict["identification_score"], style=score_style)], can
        )
        if include_trending:
            if data_dict["identification_trend_dir"] == -1:
                can.drawImage(
                    BASE_DIR + "/scorecard_assets/red_score_arrow.png",
                    6.3 * inch,
                    y_value + 0.06 * inch,
                    width=0.34 * inch,
                    height=0.3 * inch,
                    mask="auto",
                )
            elif data_dict["identification_trend_dir"] == 1:
                can.drawImage(
                    BASE_DIR + "/scorecard_assets/green_score_arrow.png",
                    6.3 * inch,
                    y_value + 0.06 * inch,
                    width=0.34 * inch,
                    height=0.3 * inch,
                    mask="auto",
                )
            else:
                can.drawImage(
                    BASE_DIR + "/scorecard_assets/grey_dot.png",
                    6.35 * inch,
                    y_value + 0.1 * inch,
                    width=0.15 * inch,
                    height=0.15 * inch,
                    mask="auto",
                )

    y_value = 7.8 * inch

    vuln_header_frame = Frame(
        col1_x_value,
        y_value + 2 * inch,
        PAGE_WIDTH - 0.6 * inch,
        0.42 * inch,
        showBoundary=False,
    )
    vuln_header_frame.addFromList(
        [Paragraph("Number of Vulnerabilities", style=header_style)], can
    )
    vulns_data = [
        ["", "KEV", "Critical", "High"],
        [
            "External Host",
            data_dict["external_host_kev"],
            data_dict["external_host_critical"],
            data_dict["external_host_high"],
        ],
        [
            "Web Applications",
            data_dict["web_app_kev"],
            data_dict["web_app_critical"],
            data_dict["web_app_high"],
        ],
        [
            "TOTALS",
            data_dict["external_host_kev"],
            data_dict["external_host_critical"] + data_dict["web_app_critical"],
            data_dict["external_host_high"] + data_dict["web_app_high"],
        ],
    ]
    vulns_table = format_table(
        vulns_data, [3.5 * inch, 1.4 * inch, 1.4 * inch, 1.4 * inch]
    )
    vulns_table_frame = Frame(
        col1_x_value, y_value, PAGE_WIDTH - 0.6 * inch, 2 * inch, showBoundary=False
    )
    vulns_table_frame.addFromList([vulns_table], can)
    # *** Generate Tracking Divider ****
    y_value = 7.3 * inch
    can.drawImage(
        BASE_DIR + "/scorecard_assets/section_divider.png",
        0,
        y_value,
        width=7.05 * inch,
        height=0.42 * inch,
        mask="auto",
    )
    tracking_frame = Frame(
        0.5 * inch, y_value + 0.04 * inch, 3 * inch, 0.42 * inch, showBoundary=False
    )
    tracking_frame.addFromList([Paragraph("TRACKING", style=divider_style)], can)
    if include_scores:
        tracking_score_frame = Frame(
            5.5 * inch if include_trending else 6 * inch,
            y_value - 0.01 * inch,
            0.8 * inch,
            0.6 * inch,
            showBoundary=False,
        )
        tracking_score_frame.addFromList(
            [Paragraph(data_dict["tracking_score"], style=score_style)], can
        )
        if include_trending:
            if data_dict["tracking_trend_dir"] == -1:
                can.drawImage(
                    BASE_DIR + "/scorecard_assets/red_score_arrow.png",
                    6.3 * inch,
                    y_value + 0.06 * inch,
                    width=0.34 * inch,
                    height=0.3 * inch,
                    mask="auto",
                )
            elif data_dict["tracking_trend_dir"] == 1:
                can.drawImage(
                    BASE_DIR + "/scorecard_assets/green_score_arrow.png",
                    6.3 * inch,
                    y_value + 0.06 * inch,
                    width=0.34 * inch,
                    height=0.3 * inch,
                    mask="auto",
                )
            else:
                can.drawImage(
                    BASE_DIR + "/scorecard_assets/grey_dot.png",
                    6.35 * inch,
                    y_value + 0.1 * inch,
                    width=0.15 * inch,
                    height=0.15 * inch,
                    mask="auto",
                )
    y_value = 4.8 * inch

    vulns_ttf_header_frame = Frame(
        col1_x_value,
        y_value + 2 * inch,
        PAGE_WIDTH - 0.6 * inch,
        0.42 * inch,
        showBoundary=False,
    )
    vulns_ttf_header_frame.addFromList(
        [
            Paragraph(
                "Average Days to Remediate Host Based Vulnerabilities",
                style=header_style,
            )
        ],
        can,
    )
    vulns_data = [
        ["", data_dict["agency_id"], data_dict["sector_name"]],
        ["KEV", data_dict["vuln_org_kev_ttr"], data_dict["vuln_sector_kev_ttr"]],
        [
            "Critical",
            data_dict["vuln_org_critical_ttr"],
            data_dict["vuln_sector_critical_ttr"],
        ],
        ["High", data_dict["vuln_org_high_ttr"], data_dict["vuln_sector_high_ttr"]],
    ]
    col_widths = [3.2 * inch, 2.1 * inch, 2.4 * inch]
    if not exclude_bods:
        vulns_data[0].append("BOD Compliance")
        vulns_data[1].append("22-01:         ")
        vulns_data[2].append("19-02:         ")
        vulns_data[3].append("19-02:         ")
        col_widths = [3.3 * inch, 1.3 * inch, 1.3 * inch, 1.8 * inch]

    vulns_table = format_table(vulns_data, col_widths)
    vulns_table_frame = Frame(
        col1_x_value, y_value, PAGE_WIDTH - 0.6 * inch, 2 * inch, showBoundary=False
    )
    vulns_table_frame.addFromList([vulns_table], can)
    if not exclude_bods:
        can.drawImage(
            BASE_DIR + "/scorecard_assets/green_check.png"
            if data_dict["vuln_bod_22-01"]
            else BASE_DIR + "/scorecard_assets/red_x.png",
            7.4 * inch,
            y_value + 81,
            width=30,
            height=25,
            mask="auto",
        )
        can.drawImage(
            BASE_DIR + "/scorecard_assets/green_check.png"
            if data_dict["vuln_critical_bod_19-02"]
            else BASE_DIR + "/scorecard_assets/red_x.png",
            7.4 * inch,
            y_value + 52,
            width=30,
            height=25,
            mask="auto",
        )
        can.drawImage(
            BASE_DIR + "/scorecard_assets/green_check.png"
            if data_dict["vuln_high_bod_19-02"]
            else BASE_DIR + "/scorecard_assets/red_x.png",
            7.4 * inch,
            y_value + 22,
            width=30,
            height=25,
            mask="auto",
        )

    y_value = 2.5 * inch

    web_app_ttf_header_frame = Frame(
        col1_x_value,
        y_value + 2 * inch,
        PAGE_WIDTH - 0.6 * inch,
        0.42 * inch,
        showBoundary=False,
    )
    web_app_ttf_header_frame.addFromList(
        [
            Paragraph(
                "Average Days to Remediate Web App Vulnerabilities", style=header_style
            )
        ],
        can,
    )
    web_app_data = [
        ["", data_dict["agency_id"], data_dict["sector_name"]],
        [
            "Critical",
            data_dict["web_app_org_critical_ttr"],
            data_dict["web_app_sector_critical_ttr"],
        ],
        ["High", data_dict["web_app_org_high_ttr"], data_dict["web_app_sector_high_ttr"]],
    ]
    web_app_table = format_table(web_app_data, [3.2 * inch, 2.1 * inch, 2.4 * inch])
    web_app_table_frame = Frame(
        col1_x_value, y_value, PAGE_WIDTH - 0.6 * inch, 2 * inch, showBoundary=False
    )
    web_app_table_frame.addFromList([web_app_table], can)

    # 'email_compliance_pct':99.3,
    # 'email_compliance_last_period':87,
    # 'https_compliance_pct':74.6,
    # 'https_compliance_last_period':80
    y_value = 0.7 * inch
    if not exclude_bods:
        bod18_header_frame = Frame(
            col1_x_value, y_value + 2 * inch, box_width, 0.42 * inch, showBoundary=False
        )
        bod18_header_frame.addFromList(
            [Paragraph("BOD 18-01", style=header_style)], can
        )
        if data_dict["email_compliance_pct"] is not None:
            email_compliance = str(data_dict["email_compliance_pct"]) + "%"
        else:
            email_compliance = "N/A"

        if data_dict["https_compliance_pct"] is not None:
            https_compliance = str(data_dict["https_compliance_pct"]) + "%"
        else:
            https_compliance = "N/A"

        if include_trending:
            bod18_data = [
                ["", "Percent", ""],
                [
                    "Email Compliance",
                    email_compliance,
                    Image(
                        determine_arrow(
                            data_dict["email_compliance_pct"],
                            data_dict["email_compliance_last_period"],
                            color=True,
                            up_is_good=True,
                        ),
                        20,
                        20,
                    ),
                ],
                [
                    "https Compliance",
                    https_compliance,
                    Image(
                        determine_arrow(
                            data_dict["https_compliance_pct"],
                            data_dict["https_compliance_last_period"],
                            color=True,
                            up_is_good=True,
                        ),
                        20,
                        20,
                    ),
                ],
            ]
            col_widths = [2.4 * inch, 1.05 * inch, 0.4 * inch]
            bod18_table = format_table(bod18_data, col_widths)
        else:
            bod18_data = [
                [
                    "",
                    "Percent",
                ],
                ["Email Compliance", email_compliance],
                ["https Compliance", https_compliance],
            ]
            col_widths = [2.5 * inch, 1.35 * inch]
            bod18_table = format_table(bod18_data, col_widths)

        bod18_table_frame = Frame(
            col1_x_value, y_value, box_width, 2 * inch, showBoundary=False
        )
        bod18_table_frame.addFromList([bod18_table], can)

    fine_print_style = ParagraphStyle(
        "fine_print_style",
        fontName="Franklin_Gothic_Book",
        fontSize=12,
    )
    fine_print_frame = Frame(
        0.25 * inch, y_value - 0.05 * inch, 8.1 * inch, 0.6 * inch, showBoundary=False
    )
    fine_print_frame.addFromList(
        [
            Paragraph(
                "*Data was last pulled on "
                + data_dict["data_pulled_date"]
                + ". Any changes made after this date will not be reflected in this scorecard.",
                style=fine_print_style,
            )
        ],
        can,
    )

    # *** Generate Footer ****
    can.drawImage(
        BASE_DIR + "/scorecard_assets/footer_banner.png",
        0,
        0,
        width=PAGE_WIDTH,
        height=0.8 * inch,
        mask="auto",
    )

    can.drawImage(
        BASE_DIR + "/scorecard_assets/cisa.png",
        PAGE_WIDTH - 1.1 * inch,
        0.1 * inch,
        width=45,
        height=45,
        mask="auto",
    )

    can.save()


# data_dict = {
#     'agency_name':'Department of Homeland Security',
#     'agency_id':'DHS',
#     'sector_name':'FCEB',
#     'date': 'February 2023',
#     'last_data_sent_date':'Jan 10, 2023', #made up
#     'ips_identified': 1221, #provided by Alex
#     "ips_monitored":1221, #provided by alex
#     'ips_trend_pct':1,
#     'domains_identified': 3866,
#     "domains_monitored":3865,
#     'domains_trend_pct':.9997,
#     'web_apps_identified': 50,
#     "web_apps_monitored":50,
#     "web_apps_trend_pct":1,
#     'certs_identified': 42,
#     "certs_monitored": 42,
#     "certs_trend_pct":0,
#     "ports_total_count":1220, #live data
#     "ports_total_trend":1234,#live data
#     "ports_risky_count": 7,#live data
#     "ports_risky_trend":9,#live data
#     "protocol_total_count":84,#live data
#     "protocol_total_trend":88,#live data
#     "protocol_insecure_count": 1,#live data
#     "protocol_insecure_trend":1,#live data
#     'services_total_count':8,#live data verify if this is total or unsupported
#     'services_total_trend':8,#live data verify if this is total or unsupported
#     'software_unsupported_count':0, #live data
#     'software_unsupported_trend':0, #live data
#     'external_host_kev':0, #live data
#     'external_host_critical':1,#live data
#     'external_host_high':1,#live data
#     'web_app_kev':'N/A',
#     'web_app_critical':4,
#     'web_app_high':0,
#     'total_kev':0, #live data
#     'total_critical':5, # depends on WAS count
#     'total_high':1, # depends on WAS count
#     'vuln_org_kev_ttr':'N/A', #live data
#     'vuln_sector_kev_ttr':0, #predicted
#     'vuln_bod_22-01':True,  #live data
#     'vuln_org_critical_ttr':29, #live data
#     'vuln_sector_critical_ttr':76, #predicted
#     'vuln_critical_bod_19-02':False, #live data
#     'vuln_org_high_ttr':35, #live data
#     'vuln_sector_high_ttr':64, #predicted
#     'vuln_high_bod_19-02':False, #live data
#     'web_app_org_critical_ttr':175, #estimated since DHS_HQ does't get WAS reports
#     'web_app_sector_crtical_ttr':202,
#     'web_app_org_high_ttr':153, #estimated since DHS_HQ does't get WAS reports
#     'web_app_sector_high_ttr':199,
#     'email_compliance_pct':98.60, #live data
#     'email_compliance_last_period':98, #made up
#     'https_compliance_pct':81.80, #live data
#     'https_compliance_last_period':80, #made up
#     'overall_score':'B',
#     'discovery_score':'A',
#     'discovery_trend_dir':1,
#     'profiling_score':'B+', #live data
#     'profiling_trend_dir':-1, #made up
#     'identification_score':'B-', #live data
#     'identification_trend_dir':0,
#     'tracking_score':'C+', #live data
#     'tracking_trend_dir':-1,
#     'data_pulled_date':'Feb. 28, 2023'
# }
