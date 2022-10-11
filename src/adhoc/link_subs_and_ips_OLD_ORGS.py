"""Serve as placeholder for docstring."""

# Third-Party Libraries
from link_subs_and_ips_from_subs import connect_ips_from_subs

# cisagov Libraries
from pe_reports.data.db_query import get_orgs_df  # connect,

orgs = get_orgs_df()
orgs = orgs[orgs["report_on"] == True]
print(orgs)

connect_ips_from_subs(orgs)
