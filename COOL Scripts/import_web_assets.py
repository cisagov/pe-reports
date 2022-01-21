"""Import web assets from a user provided csv."""
# Third-Party Libraries
import pandas as pd
from pe_db.run import connect, execute_values, query_orgs


def main():
    """Import web assets from a user provided csv."""
    orgs = query_orgs("")
    root_path = "/home/vnc/PE_Scripts/generate_orgs"
    for i, org in orgs.iterrows():

        print(f"Importing assets for {org['name']}")
        try:
            new_assets = pd.read_csv(f"{root_path}/new_ips/{org['cyhy_db_name']}.csv")
        except FileNotFoundError:
            continue

        asset_list = []
        for i, row in new_assets.iterrows():
            asset_list.append(
                {
                    "asset_type": row["Type"],
                    "asset": row["Assets"],
                    "verified": False,
                    "organizations_uid": org["organizations_uid"],
                    "asset_origin": "LG",
                    "report_on": True,
                }
            )

        asset_df = pd.DataFrame(asset_list)
        conn = connect("")
        except_clause = """ ON CONFLICT (asset, organizations_uid)
                    DO NOTHING;"""
        execute_values(conn, asset_df, "public.web_assets", except_clause)


if __name__ == "__main__":
    main()
