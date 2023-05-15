"""All task functions to gather source data for reports."""

# Standard Python Libraries
import logging
import time
import traceback

# cisagov Libraries
from pe_reports.data.tasks.celery1 import app
from pe_asm.helpers.fill_ips_from_cidrs import fill_ips_from_cidrs

# from adhoc.run_dnstwist import run_main_dnstwist


# @app.task(name="sumNumbers")
# def add(x, y):
#     """Add two numbers together"""
#     return x + y


# @app.task(name="fill_ips_from_cidrs")
# def fill_ips_task():
#     """Add two numbers together"""
#     logging.info("Filling IPS")
#     fill_ips_from_cidrs()
#     logging.info("Done Filling IPS")
#     return "Done"


# @app.task(name="run_dnstwist")
# def dnstwist_task():
#     """Run dnstwist scan."""
#     result = "Sucess"
#     try:
#         run_main_dnstwist()
#     except:
#         result = traceback.format_exc()
#     return result
