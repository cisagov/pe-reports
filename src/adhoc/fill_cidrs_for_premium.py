# Third-Party Libraries
from fill_cidrs_from_cyhy_assets import fill_cidrs

# cisagov Libraries
from pe_reports.data.db_query import connect, get_orgs_df

orgs = get_orgs_df()
orgs = orgs[orgs["report_on"] == True]
print(orgs)

fill_cidrs(orgs)
