from link_subs_and_ips_from_subs import connect_ips_from_subs
from pe_reports.data.db_query import connect, get_orgs_df


orgs = get_orgs_df()
orgs = orgs[orgs['report_on'] == True]
print(orgs)

connect_ips_from_subs(orgs)