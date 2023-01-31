"""Generate a stakeholders ASM summary based on a data dictionary."""

# Standard Python Libraries
import io
import logging
import os

# Third-Party Libraries
import fitz
from PyPDF2 import PdfReader, PdfWriter
import numpy as np
import pandas as pd
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import ParagraphStyle
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont
from reportlab.pdfgen import canvas
from reportlab.platypus import Frame, Paragraph
from reportlab.lib.enums import TA_CENTER

# cisagov Libraries
from pe_reports.data.db_query import (
    query_cidrs_by_org,
    query_foreign_IPs,
    query_ips,
    query_ports_protocols,
    query_roots,
    query_software,
    query_subs
)

# Setup logging to central file
LOGGER = logging.getLogger(__name__)

BASE_DIR = os.path.abspath(os.path.dirname(__file__))
IN_FILEPATH = BASE_DIR + "/attack_surface_empty.pdf"
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


def add_stat_frame(current_value, last_value, x, y, width, height, style, can):
    """Add data point frame."""
    show_border = False
    image_size = 22
    frame = Frame(x, y, width, height, showBoundary=show_border)
    ip_address_paragraph = Paragraph(
        f"{build_kpi_string(current_value, last_value)}",
        style=style,
    )
    frame.addFromList([ip_address_paragraph], can)
    can.drawImage(
        determine_arrow(current_value, last_value, False),
        x + 110,
        y + 16,
        image_size,
        image_size,
        mask="auto",
    )
    return can

def add_attachment(org_uid, final_output, pdf_file, asm_xlsx):

    # Create ASM Excel file
    asmWriter = pd.ExcelWriter(asm_xlsx, engine="xlsxwriter")

    # IPs
    ip_lst = query_ips(org_uid)
    ips_df = pd.DataFrame(ip_lst, columns =['ip'])
    ips_df.to_excel(
        asmWriter, sheet_name="IPs", index=False
    )

    # CIDRs
    cidr_df = query_cidrs_by_org(org_uid)
    cidr_df = cidr_df[["network"]]
    cidr_df.to_excel(
        asmWriter, sheet_name="CIDRs", index=False
    )

    # Ports/protocols
    ports_protocols_df = query_ports_protocols(org_uid)
    ports_protocols_df.to_excel(
        asmWriter, sheet_name="Ports_Protocols", index=False
    )

    # Root domains
    rd_df = query_roots(org_uid)
    rd_df = rd_df[["root_domain"]]
    rd_df.to_excel(
        asmWriter, sheet_name="Root Domains", index=False
    )

    # Sub-domains
    sd_df = query_subs(org_uid)
    sd_df = sd_df[["sub_domain"]]
    sd_df.to_excel(
        asmWriter, sheet_name="Sub-domains", index=False
    )

    # Software
    soft_df = query_software(org_uid)
    soft_df.to_excel(
        asmWriter, sheet_name="Software", index=False
    )

    # Foreign Ips
    for_ips_df = query_foreign_IPs(org_uid)
    for_ips_df = for_ips_df[["organization", "ip", "port", "protocol", "product", "country_code","location"]]
    for_ips_df.to_excel(
        asmWriter, sheet_name="Foreign IPs", index=False
    )

    asmWriter.save()

    doc = fitz.open(pdf_file)
    # Get the summary page of the PDF on page 4
    page = doc[0]

    # Open CSV data as binary
    sheet = open(asm_xlsx, "rb").read()
    p1 = fitz.Point(455, 635)
    page.add_file_annot(
        p1, sheet, "ASM_Summary.xlsx", desc="Open xlsx", icon="Paperclip"
    )
    doc.save(
        final_output,
        garbage=4,
        deflate=True,
    )

def create_summary(org_uid, final_output, data_dict, file_name, excel_filename):
    """Create ASM summary PDF."""
    packet = io.BytesIO()

    # Create a new PDF with Reportlab
    can = canvas.Canvas(packet, pagesize=letter)
    can.setFillColorRGB(0, 0, 0)  # choose your font color
    can.setFont("Frank_Goth", 20)

    org_name_style = ParagraphStyle(
        "org_name_style",
        fontName="Frank_Goth",
        fontSize=14,
        textColor="black",
        splitLongWords=1,
    )
    date_frame = Frame(73, 662, 310, 35)
    date = Paragraph(data_dict["date"], style=org_name_style)
    date_frame.addFromList([date], can)

    org_name_len = len(data_dict["org_name"])
    if org_name_len > 66:
        org_name_style.fontSize = 9
    org_name_frame = Frame(155, 635, 420, 35)
    org_name = Paragraph(data_dict["org_name"], style=org_name_style)
    org_name_frame.addFromList([org_name], can)

    stat_style = ParagraphStyle(
        "date_style", fontName="Frank_Goth_Book", fontSize=12, alignment=0
    )

    # Add all the data points to the correct frame
    can = add_stat_frame(
        data_dict["ip_address"],
        data_dict["last_ip_address"],
        25,
        353,
        180,
        50,
        stat_style,
        can,
    )
    can = add_stat_frame(
        data_dict["cidrs"], data_dict["last_cidrs"], 220, 353, 180, 50, stat_style, can
    )
    can = add_stat_frame(
        data_dict["ports_and_protocols"],
        data_dict["last_ports_and_protocols"],
        410,
        353,
        180,
        50,
        stat_style,
        can,
    )
    can = add_stat_frame(
        data_dict["root_domains"],
        data_dict["last_root_domains"],
        25,
        279,
        180,
        50,
        stat_style,
        can,
    )
    can = add_stat_frame(
        data_dict["sub_domains"],
        data_dict["last_sub_domains"],
        220,
        279,
        180,
        50,
        stat_style,
        can,
    )
    can = add_stat_frame(
        data_dict["software"],
        data_dict["last_software"],
        410,
        279,
        180,
        50,
        stat_style,
        can,
    )
    can = add_stat_frame(
        data_dict["foreign_ips"],
        data_dict["last_foreign_ips"],
        25,
        207,
        180,
        50,
        stat_style,
        can,
    )
    can.save()

    # Move to the beginning of the StringIO buffer
    packet.seek(0)
    new_pdf = PdfReader(packet)

    # Read existing PDF template
    existing_pdf = PdfReader(open(BASE_DIR + "/empty_asm.pdf", "rb"))
    output = PdfWriter()

    # Add the "watermark" (which is the new pdf) on the existing page
    page = existing_pdf.pages[0]
    page2 = new_pdf.pages[0]
    page.merge_page(page2)
    output.add_page(page)

    # Finally, write "output" to a real file
    outputStream = open(file_name, "wb")
    output.write(outputStream)
    outputStream.close()

    add_attachment(org_uid, final_output, file_name, excel_filename)
