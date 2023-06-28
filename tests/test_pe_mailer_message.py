"""This module contains the tests for the Message class."""

# Standard Python Libraries
import unittest

# cisagov Libraries
from pe_mailer.pe_message import Message


class Test(unittest.TestCase):
    """The tests for the Message class."""

    def test_one_param_single_recipient(self):
        """Test the 1-parameter version of the constructor."""
        to = ["recipient@example.com"]

        message = Message(to)

        self.assertEqual(message["From"], "reports@cyber.dhs.gov")
        self.assertEqual(message.get("CC"), None)
        self.assertEqual(
            message["BCC"], "cyhy_reports@hq.dhs.gov,reports@cyber.dhs.gov"
        )
        self.assertEqual(message["To"], "recipient@example.com")

    def test_one_param_multiple_recipients(self):
        """Test the 1-parameter version of the constructor."""
        to = ["recipient@example.com", "recipient2@example.com"]

        message = Message(to)

        self.assertEqual(message["From"], "reports@cyber.dhs.gov")
        self.assertEqual(message.get("CC"), None)
        self.assertEqual(
            message["BCC"], "cyhy_reports@hq.dhs.gov,reports@cyber.dhs.gov"
        )
        self.assertEqual(message["To"], "recipient@example.com,recipient2@example.com")

    def test_six_params_single_cc(self):
        """Test the 6-parameter version of the constructor."""
        to = ["recipient@example.com", "recipient2@example.com"]
        fm = "sender@example.com"
        cc = ["cc@example.com"]
        bcc = ["bcc@example.com"]
        subject = "The subject"
        text_body = "The plain-text body"
        html_body = "<p>The HTML body</p>"

        message = Message(
            to, subject, text_body, html_body, from_addr=fm, cc_addrs=cc, bcc_addrs=bcc
        )

        self.assertEqual(message["From"], fm)
        self.assertEqual(message["Subject"], subject)
        self.assertEqual(message["CC"], "cc@example.com")
        self.assertEqual(message["BCC"], "bcc@example.com")
        self.assertEqual(message["To"], "recipient@example.com,recipient2@example.com")

        # Make sure the correct body attachments were added
        for part in message.walk():
            # multipart/* are just containers
            if part.get_content_type() == "text/plain":
                self.assertEqual(part.get_payload(), text_body)
            elif part.get_content_type() == "text/html":
                self.assertEqual(part.get_payload(), html_body)

    def test_six_params_multiple_cc(self):
        """Test the 6-parameter version of the constructor."""
        to = ["recipient@example.com", "recipient2@example.com"]
        fm = "sender@example.com"
        cc = ["cc@example.com", "cc2@example.com"]
        bcc = ["bcc@example.com", "bcc2@example.com"]
        subject = "The subject"
        text_body = "The plain-text body"
        html_body = "<p>The HTML body</p>"

        message = Message(
            to, subject, text_body, html_body, from_addr=fm, cc_addrs=cc, bcc_addrs=bcc
        )

        self.assertEqual(message["From"], fm)
        self.assertEqual(message["Subject"], subject)
        self.assertEqual(message["CC"], "cc@example.com,cc2@example.com")
        self.assertEqual(message["BCC"], "bcc@example.com,bcc2@example.com")
        self.assertEqual(message["To"], "recipient@example.com,recipient2@example.com")

        # Make sure the correct body attachments were added
        for part in message.walk():
            # multipart/* are just containers
            if part.get_content_type() == "text/plain":
                self.assertEqual(part.get_payload(), text_body)
            elif part.get_content_type() == "text/html":
                self.assertEqual(part.get_payload(), html_body)


if __name__ == "__main__":
    unittest.main()
