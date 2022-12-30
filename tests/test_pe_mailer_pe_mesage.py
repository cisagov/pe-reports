"""This module contains the tests for the PEMessage class."""

# Standard Python Libraries
import unittest

# cisagov Libraries
from pe_mailer.pe_message import PEMessage


class Test(unittest.TestCase):
    """The tests for the PEMessage class."""

    def test_four_params_single_recipient(self):
        """Test the 4-parameter version of the constructor."""
        to = ["recipient@example.com"]
        pdf = "./tests/data/pdf-sample.pdf"
        report_date = "December 15, 2020"

        message = PEMessage(pdf, report_date, to)
        self.assertEqual(message["From"], "reports@cyber.dhs.gov")
        self.assertEqual(
            message["Subject"], "Posture and Exposure Report - December 15, 2020 (TLP:AMBER)"
        )
        self.assertEqual(message.get("CC"), None)
        self.assertEqual(
            message["BCC"], "cyhy_reports@hq.dhs.gov,reports@cyber.dhs.gov"
        )
        self.assertEqual(message["To"], "recipient@example.com")

        # Grab the bytes that comprise the attachment
        bytes = open(pdf, "rb").read()

        # Make sure the correct body and PDF attachment were added
        for part in message.walk():
            # multipart/* are just containers
            if part.get_content_type() == "application/pdf":
                self.assertEqual(part.get_payload(decode=True), bytes)
                self.assertEqual(part.get_filename(), "pdf-sample.pdf")
            elif part.get_content_type() == "text/plain":
                text_body = """Greetings,

The attached Posture and Exposure (P&E) report is the result of a CISA Cyber Assessments service that provides actionable information about public exposures and security posture weaknesses.

All of the findings and information are derived from public information that is currently available. No scanning has occurred for this service.

The report will initially be delivered twice per month, but it will be updated and enhanced to integrate more data sources and be sent with greater frequency in the future. The P&E report is for your situational awareness as a supplement to other threat reports you may have internally or externally. No action is required, but your feedback and questions are more than welcome.

Note: The report is encrypted with your Cyber Hygiene password.

Thank you,
CISA Cyber Assessments - Posture and Exposure
Cybersecurity and Infrastructure Security Agency
vulnerability@cisa.dhs.gov

WARNING: This document is FOR OFFICIAL USE ONLY (FOUO). It contains information that may be exempt from public release under the Freedom of Information Act (5 U.S.G. 552). It is to be controlled, stored, handled, transmitted, distributed, and disposed of in accordance with CISA policy relating to FOUO information and is not to be released to the public or other personnel who do not have a valid 'need-to-know' without prior approval of an authorized CISA official.
"""
                self.assertEqual(part.get_payload(), text_body)
            elif part.get_content_type() == "text/html":
                html_body = """<html>
<head></head>
<body>
<p style="color:#FFC000">TLP:AMBER</p>

<p>Greetings,</p>

<p>The attached Posture and Exposure (P&E) report is the result of a
CISA Cyber Assessments service that provides actionable information
about public exposures and security posture weaknesses.</p>

<p>All of the findings and information are derived from public
information that is currently available. No scanning has occurred
for this service.</p>

<p>The report will initially be delivered twice per month, but it
will be updated and enhanced to integrate more data sources and be
sent with greater frequency in the future. The P&E report is for your
situational awareness as a supplement to other threat reports you may
have internally or externally. No action is required, but your feedback
and questions are more than welcome.</p>

<p>Note: The report is encrypted with your Cyber Hygiene password.</p>

<p>Thank you,<br>
CISA Cyber Assessments - Posture and Exposure<br>
Cybersecurity and Infrastructure Security Agency<br>
<a href="mailto:vulnerability@cisa.dhs.gov">vulnerability@cisa.dhs.gov</a></p>

<p>WARNING: This document is FOR OFFICIAL USE ONLY (FOUO). It contains information that may be exempt from public release under the Freedom of Information Act (5 U.S.G. 552). It is to be controlled, stored, handled, transmitted, distributed, and disposed of in accordance with CISA policy relating to FOUO information and is not to be released to the public or other personnel who do not have a valid 'need-to-know' without prior approval of an authorized CISA official.</p>
</body>
</html>
"""
                self.assertEqual(part.get_payload(), html_body)

    def test_four_params_multiple_recipients(self):
        """Test the 4-parameter version of the constructor."""
        to = ["recipient@example.com", "recipient2@example.com"]
        pdf = "./tests/data/pdf-sample.pdf"
        report_date = "December 15, 2020"

        message = PEMessage(pdf, report_date, to)

        self.assertEqual(message["From"], "reports@cyber.dhs.gov")
        self.assertEqual(
            message["Subject"], "Posture and Exposure Report - December 15, 2020 (TLP:AMBER)"
        )
        self.assertEqual(message.get("CC"), None)
        self.assertEqual(
            message["BCC"], "cyhy_reports@hq.dhs.gov,reports@cyber.dhs.gov"
        )
        self.assertEqual(message["To"], "recipient@example.com,recipient2@example.com")

        # Grab the bytes that comprise the attachment
        pdf_bytes = open(pdf, "rb").read()

        # Make sure the correct body and PDF attachment were added
        for part in message.walk():
            # multipart/* are just containers
            if part.get_content_type() == "application/pdf":
                self.assertEqual(part.get_payload(decode=True), pdf_bytes)
                self.assertEqual(part.get_filename(), "pdf-sample.pdf")
            elif part.get_content_type() == "text/plain":
                text_body = """Greetings,

The attached Posture and Exposure (P&E) report is the result of a CISA Cyber Assessments service that provides actionable information about public exposures and security posture weaknesses.

All of the findings and information are derived from public information that is currently available. No scanning has occurred for this service.

The report will initially be delivered twice per month, but it will be updated and enhanced to integrate more data sources and be sent with greater frequency in the future. The P&E report is for your situational awareness as a supplement to other threat reports you may have internally or externally. No action is required, but your feedback and questions are more than welcome.

Note: The report is encrypted with your Cyber Hygiene password.

Thank you,
CISA Cyber Assessments - Posture and Exposure
Cybersecurity and Infrastructure Security Agency
vulnerability@cisa.dhs.gov

WARNING: This document is FOR OFFICIAL USE ONLY (FOUO). It contains information that may be exempt from public release under the Freedom of Information Act (5 U.S.G. 552). It is to be controlled, stored, handled, transmitted, distributed, and disposed of in accordance with CISA policy relating to FOUO information and is not to be released to the public or other personnel who do not have a valid 'need-to-know' without prior approval of an authorized CISA official.
"""
                self.assertEqual(part.get_payload(), text_body)
            elif part.get_content_type() == "text/html":
                html_body = """<html>
<head></head>
<body>
<p style="color:#FFC000">TLP:AMBER</p>

<p>Greetings,</p>

<p>The attached Posture and Exposure (P&E) report is the result of a
CISA Cyber Assessments service that provides actionable information
about public exposures and security posture weaknesses.</p>

<p>All of the findings and information are derived from public
information that is currently available. No scanning has occurred
for this service.</p>

<p>The report will initially be delivered twice per month, but it
will be updated and enhanced to integrate more data sources and be
sent with greater frequency in the future. The P&E report is for your
situational awareness as a supplement to other threat reports you may
have internally or externally. No action is required, but your feedback
and questions are more than welcome.</p>

<p>Note: The report is encrypted with your Cyber Hygiene password.</p>

<p>Thank you,<br>
CISA Cyber Assessments - Posture and Exposure<br>
Cybersecurity and Infrastructure Security Agency<br>
<a href="mailto:vulnerability@cisa.dhs.gov">vulnerability@cisa.dhs.gov</a></p>

<p>WARNING: This document is FOR OFFICIAL USE ONLY (FOUO). It contains information that may be exempt from public release under the Freedom of Information Act (5 U.S.G. 552). It is to be controlled, stored, handled, transmitted, distributed, and disposed of in accordance with CISA policy relating to FOUO information and is not to be released to the public or other personnel who do not have a valid 'need-to-know' without prior approval of an authorized CISA official.</p>
</body>
</html>
"""
                self.assertEqual(part.get_payload(), html_body)

    def test_six_params_single_cc(self):
        """Test the 6-parameter version of the constructor."""
        to = ["recipient@example.com", "recipient2@example.com"]
        pdf = "./tests/data/pdf-sample.pdf"
        fm = "sender@example.com"
        cc = ["cc@example.com"]
        bcc = ["bcc@example.com", "bcc2@example.com"]

        report_date = "December 15, 2020"

        message = PEMessage(
            pdf, report_date, to, from_addr=fm, cc_addrs=cc, bcc_addrs=bcc
        )

        self.assertEqual(message["From"], fm)
        self.assertEqual(
            message["Subject"], "Posture and Exposure Report - December 15, 2020 (TLP:AMBER)"
        )
        self.assertEqual(message["CC"], "cc@example.com")
        self.assertEqual(message["BCC"], "bcc@example.com,bcc2@example.com")
        self.assertEqual(message["To"], "recipient@example.com,recipient2@example.com")

        # Grab the bytes that comprise the attachment
        pdf_bytes = open(pdf, "rb").read()

        # Make sure the correct body and PDF attachment were added
        for part in message.walk():
            # multipart/* are just containers
            if part.get_content_type() == "application/pdf":
                self.assertEqual(part.get_payload(decode=True), pdf_bytes)
                self.assertEqual(part.get_filename(), "pdf-sample.pdf")
            elif part.get_content_type() == "text/plain":
                text_body = """Greetings,

The attached Posture and Exposure (P&E) report is the result of a CISA Cyber Assessments service that provides actionable information about public exposures and security posture weaknesses.

All of the findings and information are derived from public information that is currently available. No scanning has occurred for this service.

The report will initially be delivered twice per month, but it will be updated and enhanced to integrate more data sources and be sent with greater frequency in the future. The P&E report is for your situational awareness as a supplement to other threat reports you may have internally or externally. No action is required, but your feedback and questions are more than welcome.

Note: The report is encrypted with your Cyber Hygiene password.

Thank you,
CISA Cyber Assessments - Posture and Exposure
Cybersecurity and Infrastructure Security Agency
vulnerability@cisa.dhs.gov

WARNING: This document is FOR OFFICIAL USE ONLY (FOUO). It contains information that may be exempt from public release under the Freedom of Information Act (5 U.S.G. 552). It is to be controlled, stored, handled, transmitted, distributed, and disposed of in accordance with CISA policy relating to FOUO information and is not to be released to the public or other personnel who do not have a valid 'need-to-know' without prior approval of an authorized CISA official.
"""
                self.assertEqual(part.get_payload(), text_body)
            elif part.get_content_type() == "text/html":
                html_body = """<html>
<head></head>
<body>
<p style="color:#FFC000">TLP:AMBER</p>

<p>Greetings,</p>

<p>The attached Posture and Exposure (P&E) report is the result of a
CISA Cyber Assessments service that provides actionable information
about public exposures and security posture weaknesses.</p>

<p>All of the findings and information are derived from public
information that is currently available. No scanning has occurred
for this service.</p>

<p>The report will initially be delivered twice per month, but it
will be updated and enhanced to integrate more data sources and be
sent with greater frequency in the future. The P&E report is for your
situational awareness as a supplement to other threat reports you may
have internally or externally. No action is required, but your feedback
and questions are more than welcome.</p>

<p>Note: The report is encrypted with your Cyber Hygiene password.</p>

<p>Thank you,<br>
CISA Cyber Assessments - Posture and Exposure<br>
Cybersecurity and Infrastructure Security Agency<br>
<a href="mailto:vulnerability@cisa.dhs.gov">vulnerability@cisa.dhs.gov</a></p>

<p>WARNING: This document is FOR OFFICIAL USE ONLY (FOUO). It contains information that may be exempt from public release under the Freedom of Information Act (5 U.S.G. 552). It is to be controlled, stored, handled, transmitted, distributed, and disposed of in accordance with CISA policy relating to FOUO information and is not to be released to the public or other personnel who do not have a valid 'need-to-know' without prior approval of an authorized CISA official.</p>
</body>
</html>
"""
                self.assertEqual(part.get_payload(), html_body)

    def test_six_params_multiple_cc(self):
        """Test the 6-parameter version of the constructor."""
        to = ["recipient@example.com", "recipient2@example.com"]
        pdf = "./tests/data/pdf-sample.pdf"
        fm = "sender@example.com"
        cc = ["cc@example.com", "cc2@example.com"]
        bcc = ["bcc@example.com", "bcc2@example.com"]

        report_date = "December 15, 2020"

        message = PEMessage(
            pdf, report_date, to, from_addr=fm, cc_addrs=cc, bcc_addrs=bcc
        )

        self.assertEqual(message["From"], fm)
        self.assertEqual(
            message["Subject"], "Posture and Exposure Report - December 15, 2020 (TLP:AMBER)"
        )
        self.assertEqual(message["CC"], "cc@example.com,cc2@example.com")
        self.assertEqual(message["BCC"], "bcc@example.com,bcc2@example.com")
        self.assertEqual(message["To"], "recipient@example.com,recipient2@example.com")

        # Grab the bytes that comprise the attachment
        pdf_bytes = open(pdf, "rb").read()

        # Make sure the correct body and PDF attachment were added
        for part in message.walk():
            # multipart/* are just containers
            if part.get_content_type() == "application/pdf":
                self.assertEqual(part.get_payload(decode=True), pdf_bytes)
                self.assertEqual(part.get_filename(), "pdf-sample.pdf")
            elif part.get_content_type() == "text/plain":
                text_body = """Greetings,

The attached Posture and Exposure (P&E) report is the result of a CISA Cyber Assessments service that provides actionable information about public exposures and security posture weaknesses.

All of the findings and information are derived from public information that is currently available. No scanning has occurred for this service.

The report will initially be delivered twice per month, but it will be updated and enhanced to integrate more data sources and be sent with greater frequency in the future. The P&E report is for your situational awareness as a supplement to other threat reports you may have internally or externally. No action is required, but your feedback and questions are more than welcome.

Note: The report is encrypted with your Cyber Hygiene password.

Thank you,
CISA Cyber Assessments - Posture and Exposure
Cybersecurity and Infrastructure Security Agency
vulnerability@cisa.dhs.gov

WARNING: This document is FOR OFFICIAL USE ONLY (FOUO). It contains information that may be exempt from public release under the Freedom of Information Act (5 U.S.G. 552). It is to be controlled, stored, handled, transmitted, distributed, and disposed of in accordance with CISA policy relating to FOUO information and is not to be released to the public or other personnel who do not have a valid 'need-to-know' without prior approval of an authorized CISA official.
"""
                self.assertEqual(part.get_payload(), text_body)
            elif part.get_content_type() == "text/html":
                html_body = """<html>
<head></head>
<body>
<p style="color:#FFC000">TLP:AMBER</p>

<p>Greetings,</p>

<p>The attached Posture and Exposure (P&E) report is the result of a
CISA Cyber Assessments service that provides actionable information
about public exposures and security posture weaknesses.</p>

<p>All of the findings and information are derived from public
information that is currently available. No scanning has occurred
for this service.</p>

<p>The report will initially be delivered twice per month, but it
will be updated and enhanced to integrate more data sources and be
sent with greater frequency in the future. The P&E report is for your
situational awareness as a supplement to other threat reports you may
have internally or externally. No action is required, but your feedback
and questions are more than welcome.</p>

<p>Note: The report is encrypted with your Cyber Hygiene password.</p>

<p>Thank you,<br>
CISA Cyber Assessments - Posture and Exposure<br>
Cybersecurity and Infrastructure Security Agency<br>
<a href="mailto:vulnerability@cisa.dhs.gov">vulnerability@cisa.dhs.gov</a></p>

<p>WARNING: This document is FOR OFFICIAL USE ONLY (FOUO). It contains information that may be exempt from public release under the Freedom of Information Act (5 U.S.G. 552). It is to be controlled, stored, handled, transmitted, distributed, and disposed of in accordance with CISA policy relating to FOUO information and is not to be released to the public or other personnel who do not have a valid 'need-to-know' without prior approval of an authorized CISA official.</p>
</body>
</html>
"""
                self.assertEqual(part.get_payload(), html_body)


if __name__ == "__main__":
    unittest.main()
