"""Need to insert docstring here."""
# Standard Python Libraries
import os
import sys

# Third-Party Libraries
from pages import Pages
from pptx import Presentation

# Configuration
SAVE_PATH = "cyhy/pe-reports/output"
REPORT_SHELL = "cyhy/pe-reports/data/shell/pe_shell.pptx"


def load_template():
    """Need to insert docstring here."""
    prs = Presentation(REPORT_SHELL)
    return prs


def export_set(prs):
    """Need to insert docstring here."""
    pptx_out = "Customer_ID_Posture_Exposure.pptx"
    prs.save(os.path.join(SAVE_PATH, pptx_out))
    return


def main():
    """Need to insert docstring here."""
    print("\n [Info] Loading Posture & Exposure Report Template")
    prs = load_template()

    print("\n [Info] Generating Graphs ")
    Pages.cover(prs)
    Pages.overview(prs)
    # Pages.credential(prs)
    # Pages.masquerading(prs)
    # Pages.mal_vul(prs, data)
    # Pages.dark_web((prs, data)
    # Pages.supplimental(prs, data)

    print("\n [Info] File Saved: ../output/Customer_ID_Posture_Exposure.pptx")
    export_set(prs)


if __name__ == "__main__":
    sys.exit(main())
