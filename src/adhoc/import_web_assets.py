"""Import web assets."""
# Third-Party Libraries
from data.run import connect, execute_values, getDataSource, query_orgs
import pandas as pd

orgs = query_orgs("")
root_path = "/home/ubuntu/adhoc"
for org_index, org in orgs.iterrows():

    print(f"Importing assets for {org['name']}")
    try:
        new_assets = pd.read_csv(f"{root_path}/new_ips/{org['cyhy_db_name']}.csv")
    except FileNotFoundError:
        continue

    asset_list = []
    for asset_index, asset_row in new_assets.iterrows():
        source_uid = getDataSource(asset_row["Source"])[0]
        asset_list.append(
            {
                "asset_type": asset_row["Type"],
                "asset": asset_row["Assets"],
                "verified": False,
                "organizations_uid": org["organizations_uid"],
                "asset_origin": "LG",
                "report_on": True,
                "data_source_uid": source_uid,
            }
        )

    asset_df = pd.DataFrame(asset_list)
    conn = connect("")
    except_clause = """ ON CONFLICT (asset, organizations_uid)
                DO NOTHING;"""
    execute_values(conn, asset_df, "public.web_assets", except_clause)
