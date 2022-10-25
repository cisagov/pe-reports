"""Collect Shodan data."""

# Standard Python Libraries
import threading

# Third-Party Libraries
import numpy

from .data.pe_db.config import shodan_api_init
from .data.pe_db.db_query_source import get_orgs
from .data.shodan.shodan_search import run_shodan_thread


class Shodan:
    """Fetch Shodan data."""

    def __init__(self, orgs_list):
        """Initialize Shodan class."""
        self.orgs_list = orgs_list

    def run_shodan(self):
        """Run Shodan calls."""
        orgs_list = self.orgs_list

        # Get orgs from PE database
        pe_orgs = get_orgs()

        # Filter orgs if specified
        if orgs_list == "all":
            pe_orgs_final = pe_orgs
        else:
            pe_orgs_final = []
            for pe_org in pe_orgs:
                if pe_org["cyhy_db_name"] in orgs_list:
                    pe_orgs_final.append(pe_org)
                else:
                    continue

        # Get list of initialized API objects
        api_list = shodan_api_init()

        # Split orgs into chunks. # of chunks = # of valid API keys = # of threads
        chunk_size = len(api_list)
        chunked_orgs_list = numpy.array_split(numpy.array(pe_orgs_final), chunk_size)

        i = 0
        thread_list = []
        while i < len(chunked_orgs_list):
            thread_name = f"Thread {i+1}:"
            # Start thread
            t = threading.Thread(
                target=run_shodan_thread,
                args=(api_list[i], chunked_orgs_list[i], thread_name),
            )
            t.start()
            thread_list.append(t)
            i += 1

        # Wait until all threads finish to continue
        for thread in thread_list:
            thread.join()
