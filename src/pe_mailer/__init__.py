"""The pe_mailer library."""
# We disable a Flake8 check for "Module imported but unused (F401)" here because
# although this import is not directly used, it populates the value
# package_name.__version__, which is used to get version information about this
# Python package.

__all__ = ["email_reports", "message", "pe_message", "report_message"]