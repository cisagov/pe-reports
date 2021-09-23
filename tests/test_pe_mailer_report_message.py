"""This module contains the tests for the ReportMessage class."""

# Standard Python Libraries
import unittest

# cisagov Libraries
from pe_mailer.report_message import ReportMessage


class Test(unittest.TestCase):
    """The tests for the ReportMessage class."""

    def test_five_params(self):
        """Test the 5-parameter version of the constructor."""
        to = ["recipient@example.com"]
        pdf = "./tests/data/pdf-sample.pdf"
        subject = "The subject"
        text_body = "The plain-text body"
        html_body = "<p>The HTML body</p>"

        message = ReportMessage(to, subject, text_body, html_body, pdf)

        self.assertEqual(message["From"], "reports@cyber.dhs.gov")
        self.assertEqual(message["Subject"], subject)
        self.assertEqual(message.get("CC"), None)
        self.assertEqual(
            message["BCC"], "cyhy_reports@hq.dhs.gov,reports@cyber.dhs.gov"
        )
        self.assertEqual(message["To"], "recipient@example.com")

        # Grab the bytes that comprise the attachment
        bytes = open(pdf, "rb").read()

        # Make sure the correct body and PDF attachments were added
        for part in message.walk():
            # multipart/* are just containers
            if part.get_content_type() == "application/pdf":
                self.assertEqual(part.get_payload(decode=True), bytes)
                self.assertEqual(part.get_filename(), "pdf-sample.pdf")
            elif part.get_content_type() == "text/plain":
                self.assertEqual(part.get_payload(), text_body)
            elif part.get_content_type() == "text/html":
                self.assertEqual(part.get_payload(), html_body)

    def test_seven_params(self):
        """Test the 7-parameter version of the constructor."""
        to = ["recipient@example.com"]
        pdf = "./tests/data/pdf-sample.pdf"
        subject = "The subject"
        text_body = "The plain-text body"
        html_body = "<p>The HTML body</p>"
        fm = "sender@example.com"
        cc = ["cc@example.com"]
        bcc = ["bcc@example.com"]

        message = ReportMessage(to, subject, text_body, html_body, pdf, fm, cc, bcc)

        self.assertEqual(message["From"], "sender@example.com")
        self.assertEqual(message["Subject"], subject)
        self.assertEqual(message["CC"], "cc@example.com")
        self.assertEqual(message["BCC"], "bcc@example.com")
        self.assertEqual(message["To"], "recipient@example.com")

        # Grab the bytes that comprise the attachment
        bytes = open(pdf, "rb").read()

        # Make sure the correct body and PDF attachments were added
        for part in message.walk():
            # multipart/* are just containers
            if part.get_content_type() == "application/pdf":
                self.assertEqual(part.get_payload(decode=True), bytes)
                self.assertEqual(part.get_filename(), "pdf-sample.pdf")
            elif part.get_content_type() == "text/plain":
                self.assertEqual(part.get_payload(), text_body)
            elif part.get_content_type() == "text/html":
                self.assertEqual(part.get_payload(), html_body)


if __name__ == "__main__":
    unittest.main()
