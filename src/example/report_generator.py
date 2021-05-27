"""ciagov/pe-reports: A tool for creating Posture & Exposure reports."""

# Standard Python Libraries
import os
import sys

# Third-Party Libraries
from _version import __version__
from pages import Pages
from pptx import Presentation

# Configuration
SAVE_PATH = "src/pe_reports/output"
REPORT_SHELL = "src/pe_reports/data/shell/pe_shell.pptx"


def load_template():
    """Load PowerPoint template into memory."""
    prs = Presentation(REPORT_SHELL)
    return prs


def export_set(prs):
    """Export PowerPoint report set to output directory."""
    pptx_out = "Customer_ID_Posture_Exposure.pptx"
    prs.save(os.path.join(SAVE_PATH, pptx_out))
    return


def main():
    """Generate PDF reports."""
    print("\n [Info] Loading Posture & Exposure Report Template, Version:", __version__)
    prs = load_template()

    print("\n [Info] Generating Graphs ")
    Pages.cover(prs)
    Pages.overview(prs)
    export_set(prs)


if __name__ == "__main__":
    sys.exit(main())
