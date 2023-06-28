"""Fill cyhy assets."""
# Third-Party Libraries
from data.run import connect, execute_values
import pandas as pd

assets = pd.read_csv("cyhy_data/cyhy_assets.csv")
contacts = pd.read_csv("cyhy_data/cyhy_contacts.csv")
conn = connect("")
# cur = conn.cursor()
# delete_sql = """DELETE FROM cyhy_db_assets;"""
# cur.execute(delete_sql)
# conn.commit()
# cur.close()
assets = assets.drop(columns=["Unnamed: 0"])
contacts = contacts.drop(columns=["Unnamed: 0"])

print(assets)
conflict = """
 ON CONFLICT (org_id, network)
    DO UPDATE SET contact = EXCLUDED.contact, org_name = EXCLUDED.org_name, type = EXCLUDED.type;
"""
execute_values(conn, assets, "cyhy_db_assets", conflict)

conflict = """
     ON CONFLICT (org_id, contact_type, email, name)
    DO UPDATE SET  org_name = EXCLUDED.org_name, phone = EXCLUDED.phone, date_pulled = EXCLUDED.date_pulled;
"""
contacts.drop_duplicates(
    subset=["org_id", "name", "contact_type", "email"], inplace=True, ignore_index=True
)
# contacts = contacts[contacts.duplicated(['org_id','name','contact_type','email'],keep=False)]
print(contacts)
execute_values(conn, contacts, "cyhy_contacts", conflict)
