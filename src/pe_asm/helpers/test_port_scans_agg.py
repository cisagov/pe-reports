"""test_port_scans_agg.py script."""
# Standard Python Libraries
import datetime

# Third-Party Libraries
import pandas as pd

# from pymongo import MongoClient

one_month_ago = datetime.datetime.now() - datetime.timedelta(days=30)
client = pd.DataFrame()
cyhyDB = client["cyhy"]
port_scans = cyhyDB["snapshots"]


pipeline = [
    {
        "$lookup": {
            "from": "requests",
            "localField": "owner",
            "foreignField": "_id",
            "as": "owner_data",
        }
    },
    {"$unwind": "$owner_data"},
    {
        "$match": {
            "owner_data.agency.type": "FEDERAL",
            "end_time": {"$gte": one_month_ago},
        }
    },
    {"$count": "total_count"},
]
port_scans_data = port_scans.aggregate(pipeline)
for scan in port_scans_data:
    port_scans_total = scan["total_count"]

print("%d total documents", port_scans_total)
port_scans_agg = port_scans.aggregate(pipeline)

for scan in port_scans_agg:
    port_scans_total = scan["total_count"]

print(port_scans_total)

# Reset the pipeline to exclude the $count stage
pipeline.pop()

port_scans_agg = port_scans.aggregate(pipeline)

for value in port_scans_agg:
    # print(value)
    print(value["owner_data"]["agency"]["type"])
# print(port_scans_agg)
