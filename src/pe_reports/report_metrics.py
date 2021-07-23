"""Gather report metrics to load into reports."""
# Standard Python Libraries
from datetime import datetime
import json
import re

# Third-Party Libraries
import pandas as pd


def credential_metrics(idx, df):
    """Calculate compromised credentials metrics and return variables and dataframes."""
    # Total incidents
    inc = len(df)

    if inc > 0:
        # Format dates
        df["Date of discovery"] = df.timestamp.apply(
            lambda x: datetime.strptime(x, "%Y-%m-%dT%H:%M:%S%z").strftime("%m/%d/%Y")
        )

        # Create df: Number of incidents per source
        inc_src_df = df.groupby("network").size().reset_index()
        inc_src_df.columns = ["source", "count"]

        # Create df: Number of incidents by date
        inc_date_df = df.groupby("Date of discovery").size().reset_index()
        inc_date_df.columns = ["Date of discovery", "Incident count"]
        # Reindex the df to include all dates
        inc_date_df.index = pd.DatetimeIndex(inc_date_df["Date of discovery"]).strftime(
            "%m/%d/%Y"
        )
        inc_date_df = inc_date_df.reindex(idx, fill_value=0).drop(
            ["Date of discovery"], axis=1
        )
        inc_date_df["Date of discovery"] = inc_date_df.index

        # Create df: Number of credentials exposed per incident
        count = []
        emails = []
        raw_count = []
        for index, row in df.iterrows():
            incident_data = json.loads(row["metadata"])
            raw_data = incident_data["content_raw_data"]["data"]
            raw_emails = re.findall("[a-zA-Z0-9+_.-]+@[a-zA-Z0-9.-]+", raw_data)
            emails.append(raw_emails)
            if len(raw_emails) >= 20:
                count.append("  20+")
            else:
                count.append(len(raw_emails))
            raw_count.append(len(raw_emails))
        df["Credentials Exposed"] = count
        df["Emails"] = emails
        num_inc_idx = list(range(1, 20))
        num_inc_idx.append("  20+")
        ce_inc_df = df.groupby("Credentials Exposed").size().reset_index()
        ce_inc_df.columns = ["Credential count per incidents", "Incident count"]
        # Reindex to include all counts and 20+
        ce_inc_df.index = ce_inc_df["Credential count per incidents"]
        ce_inc_df = ce_inc_df.reindex(num_inc_idx, fill_value=0).drop(
            ["Credential count per incidents"], axis=1
        )
        ce_inc_df["Credential count per incidents"] = ce_inc_df.index
        ce_inc_df["Credential count per incidents"] = ce_inc_df[
            "Credential count per incidents"
        ].astype(str)

        # Create df: data to be returned as csv
        creds_attach = df[
            [
                "offending_content_url",
                "content_created_at",
                "timestamp",
                "severity",
                "perpetrator",
                "network",
                "Credentials Exposed",
                "Emails",
            ]
        ]

        # Total credentials exposed
        creds = sum(raw_count)

    else:
        creds = 0
        inc_src_df = pd.DataFrame([["", 0]], columns=["source", "count"])
        inc_date_df = pd.DataFrame(
            data={"Date of discovery": idx, "Incident count": [0] * 15}
        )
        ce_inc_df = pd.DataFrame(
            [[0, 0]], columns=["Credential count per incidents", "Incident count"]
        )
        creds_attach = pd.DataFrame(
            columns=[
                "offending_content_url",
                "content_created_at",
                "timestamp",
                "severity",
                "perpetrator",
                "network",
                "Credentials Exposed",
                "Emails",
            ]
        )

    return inc, creds, inc_src_df, inc_date_df, ce_inc_df, creds_attach


def domain_metrics(idx, df):
    """Calculate domain metrics and return variables and dataframes."""
    # Total domains suspected of masquearding
    domains = len(df)
    if domains > 0:
        # Format dates, domain, and tld columns
        df["Date observed"] = df.timestamp.apply(
            lambda x: datetime.strptime(x, "%Y-%m-%dT%H:%M:%S%z").strftime("%m/%d/%Y")
        )
        df["domain"] = df.offending_content_url.str.split("?").str[0]
        df["tld"] = df.domain.str.split(".").str[-1].str.split("/").str[0]

        # Create df: number of domains per tld
        tld_df = df.groupby("tld").size().reset_index()
        tld_df.columns = ["tld", "count"]

        # Total unique tld's
        utld = len(tld_df)

        # Create df: number of domains observed by date
        dm_df = df[["domain", "Date observed"]]
        dm_df.columns = ["Suspected masquerading domains", "Date observed"]
        # Sample of latest 5 domains observed
        dm_samp = dm_df[:5]
        dm_df = dm_df.groupby("Date observed").size().reset_index()
        dm_df.columns = ["Date of discovery", "Domain count"]
        # reindex the grouped discoveries to include all dates
        dm_df.index = pd.DatetimeIndex(dm_df["Date of discovery"]).strftime("%m/%d/%Y")
        dm_df = dm_df.reindex(idx, fill_value=0).drop(["Date of discovery"], axis=1)
        dm_df["Date of discovery"] = dm_df.index
        dm_df = dm_df.reset_index(drop=True)
        dm_df = dm_df[["Date of discovery", "Domain count"]]

        # Create df: data to be returned as csv
        domains_attach = df[
            ["domain", "tld", "Date observed", "severity", "logs", "tags"]
        ]

    else:
        utld = 0
        tld_df = pd.DataFrame([["", 0]], columns=["tld", "count"])
        dm_samp = pd.DataFrame(columns=["domain", "Date Observed"])
        dm_df = pd.DataFrame(data={"Date of discovery": idx, "Domain count": [0] * 15})
        domains_attach = pd.DataFrame(
            columns=["domain", "tld", "Date observed", "severity", "logs", "tags"]
        )

    return domains, utld, tld_df, dm_df, dm_samp, domains_attach


def malware_vuln_metrics(m_df, v_df, start_date, end_date):
    """Calculate malware association and inferred vulnerability metrics and return variables and dataframes."""
    # Total malware associations
    malware = len(m_df)
    # Total Inferred Vulnerabilities
    vulns = len(v_df)

    if malware > 0:
        # Format dates
        m_df["LastObserved"] = m_df.lastSeen.apply(
            lambda x: datetime.utcfromtimestamp(x / 1000)
        )
        m_df["FirstObserved"] = m_df.firstSeen.apply(
            lambda x: datetime.utcfromtimestamp(x / 1000)
        )
        m_df["Days between first and last observation"] = (
            m_df["LastObserved"] - m_df["FirstObserved"]
        ).dt.days
        m_df["Last Observed"] = m_df.LastObserved.apply(
            lambda x: x.strftime("%m/%d/%Y")
        )
        m_df["First Observed"] = m_df.FirstObserved.apply(
            lambda x: x.strftime("%m/%d/%Y")
        )

        # Create Asset, Asset Type, Name, Classification, and Category Columns
        asset = []
        classifications = []
        name = []
        asset_type = []
        for index, row in m_df.iterrows():
            # k = eval(row["right"])
            classifications.append(", ".join(k["classifications"]))
            name.append(k["name"])
            # lft = eval(row["left"])
            asset_type.append(lft["type"])
            asset.append(lft["name"])
        m_df["Asset"] = asset
        m_df["Asset Type"] = asset_type
        m_df["Name"] = name
        m_df["Classifications"] = classifications
        m_df["Category"] = "Malware Associations"

        # Number of unique malware threats
        uma = len(pd.unique(m_df["Name"]))

        # Create df: active malware associations
        ma_act_df = m_df.groupby("Name").size().reset_index()
        ma_act_df.columns = ["Name", "size"]
        ma_act_df["Percentage"] = (ma_act_df["size"] / ma_act_df["size"].sum()) * 100
        ma_act_df = ma_act_df.round(0)
        ma_act_df.columns = ["Name", "Associations count", "Percentage"]

        # Create df: sample of 5 malware associations
        ma_samp = m_df[["Asset", "Classifications", "Last Observed"]]
        # ma_samp["Classifications"] = ma_samp["Classifications"]
        ma_samp = ma_samp[:5]

        # Create df: data to be returned as csv
        ma_attach = m_df[
            ["Asset", "Asset Type", "Name", "First Observed", "Last Observed"]
        ]

    else:
        uma = 0
        ma_act_df = pd.DataFrame(
            [["", 0, 0]], columns=["Name", "Associations count", "Percentage"]
        )
        ma_samp = pd.DataFrame(
            columns=["Assets with inferred vulnerabilities", "Date last observed"]
        )
        ma_attach = pd.DataFrame(
            columns=["Asset", "Asset Type", "Name", "First Observed", "Last Observed"]
        )

    if vulns > 0:
        # Format dates
        v_df["LastObserved"] = v_df.lastSeen.apply(
            lambda x: datetime.utcfromtimestamp(x / 1000)
        )
        v_df["FirstObserved"] = v_df.firstSeen.apply(
            lambda x: datetime.utcfromtimestamp(x / 1000)
        )
        v_df["Days between first and last observation"] = (
            v_df["LastObserved"] - v_df["FirstObserved"]
        ).dt.days
        v_df["Last Observed"] = v_df.LastObserved.apply(
            lambda x: x.strftime("%m/%d/%Y")
        )
        v_df["First Observed"] = v_df.FirstObserved.apply(
            lambda x: x.strftime("%m/%d/%Y")
        )

        # Create Asset, Asset Type, Name, Classification, and Category Columns
        asset = []
        classifications = []
        name = []
        asset_type = []
        for index, row in v_df.iterrows():
            k = eval(row["right"])
            classifications.append(k["classifications"])
            name.append(k["name"])
            lft = eval(row["left"])
            asset_type.append(lft["type"])
            asset.append(lft["name"])
        v_df["Asset"] = asset
        v_df["Asset Type"] = asset_type
        v_df["Name"] = name
        v_df["Classifications"] = classifications
        v_df["Category"] = "Inferred Vulnerabilities"

        # Create df: iv_df: Proportion of inferred vulnss by classification
        v_df["Short Name"] = v_df["Name"].str.split(" - ").str[-1]
        iv_df = v_df.groupby("Short Name").size().reset_index()
        iv_df.columns = ["Name", "size"]
        iv_df["Percentage"] = (iv_df["size"] / iv_df["size"].sum()) * 100
        # Create df: iv_act_df: Number of inferred vulns by classification
        iv_act_df = iv_df[["Name", "size"]]
        iv_act_df.columns = ["Name", "Associations count"]
        iv_df = iv_df[["Name", "Percentage"]]
        iv_df = iv_df.round(0)

        # Create df: Sample of inferred vulns
        iv_samp = v_df[["Asset", "Last Observed"]]
        iv_samp.columns = ["Assets with inferred vulnerabilities", "Date last observed"]
        iv_samp = iv_samp[:5]

        # Create df: inferred vuln data to be returned as csv
        vuln_attach = v_df[
            ["Asset", "Asset Type", "Name", "First Observed", "Last Observed"]
        ]

    else:
        iv_df = pd.DataFrame([["", 0]], columns=["Name", "Percentage"])
        iv_act_df = pd.DataFrame([["", 0]], columns=["Name", "Associations count"])
        vuln_attach = pd.DataFrame(
            columns=["Asset", "Asset Type", "Name", "First Observed", "Last Observed"]
        )
        iv_samp = pd.DataFrame(
            columns=["Assets with inferred vulnerabilities", "Date last observed"]
        )

    if vulns > 0 or malware > 0:
        # combined malware and inferred vuln data
        combined_df = pd.concat([m_df, v_df])

        # Number of unique vuln or malware assets
        assets = len(pd.unique(combined_df["Asset"]))

        # Create df: Date of last observation for active malware and inferred vulns
        vuln_ma_df = (
            combined_df.groupby(["Category", "Last Observed"]).size().reset_index()
        )
        vuln_ma_df.columns = [
            "Category",
            "Date of last observation",
            "Associations count",
        ]
        vuln_ma_df = (
            vuln_ma_df.pivot(
                index="Date of last observation",
                columns="Category",
                values="Associations count",
            )
            .fillna(0)
            .reset_index()
            .rename_axis(None)
        )
        vuln_ma_df.columns.name = None
        vuln_ma_df.index.name = None
        vuln_ma_df["Date of last observation"] = pd.to_datetime(
            vuln_ma_df["Date of last observation"], format="%m/%d/%Y"
        )
        r = pd.date_range(start_date, end_date)
        vuln_ma_df = (
            vuln_ma_df.set_index("Date of last observation")
            .reindex(r, fill_value=0)
            .rename_axis("Date of last observation")
            .reset_index()
        )
        vuln_ma_df["Date of last observation"] = vuln_ma_df[
            "Date of last observation"
        ].dt.strftime("%m/%d/%Y")

        if "Inferred Vulnerabilities" not in vuln_ma_df.columns:
            vuln_ma_df["Inferred Vulnerabilities"] = 0
        if "Malware Associations" not in vuln_ma_df.columns:
            vuln_ma_df["Malware Associations"] = 0

        # Create df: Total days betwen first and last observation for inferred vulns and malware
        vuln_ma_df2 = (
            combined_df.groupby(["Category", "Days between first and last observation"])
            .size()
            .reset_index()
        )
        vuln_ma_df2.columns = [
            "Category",
            "Days between first and last observation",
            "Associations count",
        ]
        Over_30 = vuln_ma_df2[
            vuln_ma_df2["Days between first and last observation"] >= 20
        ]
        Mals_Over_30 = Over_30.loc[
            Over_30["Category"] == "Malware Associations", "Associations count"
        ].sum()
        Vulns_Over_30 = Over_30.loc[
            Over_30["Category"] == "Inferred Vulnerabilities", "Associations count"
        ].sum()
        vuln_ma_df2 = vuln_ma_df2[
            vuln_ma_df2["Days between first and last observation"] < 20
        ]
        vuln_ma_df2 = (
            vuln_ma_df2.pivot(
                index="Days between first and last observation",
                columns="Category",
                values="Associations count",
            )
            .fillna(0)
            .reset_index()
            .rename_axis(None)
        )
        vuln_ma_df2.columns.name = None
        vuln_ma_df2 = (
            vuln_ma_df2.set_index("Days between first and last observation")
            .reindex(range(0, 20), fill_value=0)
            .rename_axis("Days between first and last observation")
            .reset_index()
        )
        vuln_ma_df2["Days between first and last observation"] = vuln_ma_df2[
            "Days between first and last observation"
        ].astype(str)
        vuln_ma_df2 = vuln_ma_df2.append(
            pd.DataFrame(
                [["  20+", Vulns_Over_30, Mals_Over_30]],
                columns=[
                    "Days between first and last observation",
                    "Inferred Vulnerabilities",
                    "Malware Associations",
                ],
            )
        ).reset_index(drop=True)
    else:
        vuln_ma_df = pd.DataFrame(
            [["", 0, 0, 0, 0]],
            columns=[
                "Category",
                "Date of last observation",
                "Associations count",
                "Inferred Vulnerabilities",
                "Malware Associations",
            ],
        )
        vuln_ma_df2 = pd.DataFrame(
            [["", 0, 0, 0, 0]],
            columns=[
                "Category",
                "Date of last observation",
                "Associations count",
                "Inferred Vulnerabilities",
                "Malware Associations",
            ],
        )
        assets = 0

    return (
        malware,
        uma,
        ma_act_df,
        ma_samp,
        ma_attach,
        vulns,
        iv_df,
        iv_act_df,
        iv_samp,
        vuln_attach,
        vuln_ma_df,
        vuln_ma_df2,
        assets,
    )


def mention_metrics(idx, df):
    """Calculate malware association metrics and return variables and dataframes."""
    # Total web mentions
    web = len(df)
    if web > 0:
        # Format dates and darkweb vs. web categories
        df["Date of mention"] = df.timestamp.apply(
            lambda x: datetime.strptime(x, "%Y-%m-%dT%H:%M:%S%z").strftime("%m/%d/%Y")
        )
        df["Category"] = df.network.apply(
            lambda x: '"Dark web"'
            if x == "tor" or x == "i2p" or x == "darkweb"
            else "Web"
        )

        # Number of Dark Web mentions
        dark = len(df[df["Category"] == '"Dark web"'])

        # Create df: Web and dark web mentions over time
        web_df = df.groupby(["Category", "Date of mention"]).size().reset_index()
        web_df.columns = ["Category", "Date of mention", "Mentions count"]

        # Create dfs: Web only and dark web only data by date
        dark_web_df = web_df[web_df["Category"] == '"Dark web"']
        web_only_df = web_df[web_df["Category"] == "Web"]
        # reindex to include all dates
        dark_web_df.index = pd.DatetimeIndex(dark_web_df["Date of mention"]).strftime(
            "%m/%d/%Y"
        )
        dark_web_df = dark_web_df.reindex(idx, fill_value=0).drop(
            ["Date of mention"], axis=1
        )
        dark_web_df["Date of mention"] = dark_web_df.index
        web_only_df.index = pd.DatetimeIndex(web_only_df["Date of mention"]).strftime(
            "%m/%d/%Y"
        )
        web_only_df = web_only_df.reindex(idx, fill_value=0).drop(
            ["Date of mention"], axis=1
        )
        web_only_df["Date of mention"] = web_only_df.index

        # Create df: Web mention grouped by source
        web_source_df = df.groupby("network").size().reset_index()
        web_source_df = web_source_df[web_source_df["network"] != "darkweb"]
        web_source_df = web_source_df.reset_index(drop=True)
        web_source_df.columns = ["Source of mention", "Mentions count"]
        web_source_df["Source of mention"] = web_source_df[
            "Source of mention"
        ].str.replace("_", " ")

        # Create df: Web mention data to be returned as csv
        web_copy = df[
            [
                "Category",
                "network",
                "Date of mention",
                "severity",
                "perpetrator",
                "darkweb_term",
                "protected_social_object",
            ]
        ]
        # Expand the perpetrator object into 5 seperate columns
        # There's probably a better way to do this...
        web_attach = web_copy.copy(deep=False)
        names = (
            web_attach["perpetrator"]
            .str.split("name': ")
            .str[1]
            .str.split(", 'display")
            .str[0]
        )
        web_attach["name"] = names

        displays = (
            web_attach["perpetrator"]
            .str.split("display_name': ")
            .str[1]
            .str.split(", 'id")
            .str[0]
        )
        web_attach["display_name"] = displays

        urls = (
            web_attach["perpetrator"]
            .str.split("url': ")
            .str[1]
            .str.split(", 'content")
            .str[0]
        )
        web_attach["url"] = urls

        types = (
            web_attach["perpetrator"]
            .str.split("type': ")
            .str[1]
            .str.split(", 'time")
            .str[0]
        )
        web_attach["type"] = types

        contents = (
            web_attach["perpetrator"]
            .str.split("content': ")
            .str[1]
            .str.split(", 'type")
            .str[0]
        )
        web_attach["content"] = contents

        # Only display the content of Dark web mentions to reduce size
        mask = web_attach["Category"] == "Web"
        web_attach.loc[mask, "content"] = "See link"

        # Drop the perpetrator column which has been expanded
        web_attach = web_attach.drop("perpetrator", 1)

    else:
        web_df = pd.DataFrame(columns=["Category", "Date of mention", "Mentions count"])
        web_source_df = pd.DataFrame(columns=["Source of mention", "Mentions count"])
        dark = 0
        web_attach = pd.DataFrame(
            columns=[
                "Category",
                "network",
                "Date of mention",
                "severity",
                "darkweb_term",
                "protected_social_object",
                "name",
                "display_name",
                "url",
                "type",
                "content",
            ]
        )

    return web, dark, web_df, web_source_df, web_attach, dark_web_df, web_only_df


def generate_metrics(datestring, cred_df, dom_df, mal_df, inferred_df, men_df):
    """Gather all data points for each metric type."""
    # Format start_date and end_date
    end_date = datetime.strptime(datestring, "%Y-%m-%d").date()
    if end_date.day == 15:
        start_date = datetime(end_date.year, end_date.month, 1)
    else:
        start_date = datetime(end_date.year, end_date.month, 16)
    idx = pd.date_range(start_date, end_date).strftime("%m/%d/%Y")

    # Generate metrics from each dataframe
    inc, creds, inc_src_df, inc_date_df, ce_inc_df, creds_attach = credential_metrics(
        idx, cred_df
    )
    domains, utld, tld_df, dm_df, dm_samp, domains_attach = domain_metrics(idx, dom_df)
    (
        malware,
        uma,
        ma_act_df,
        ma_samp,
        ma_attach,
        vulns,
        iv_df,
        iv_act_df,
        iv_samp,
        iv_attach,
        vuln_ma_df,
        vuln_ma_df2,
        assets,
    ) = malware_vuln_metrics(mal_df, inferred_df, start_date, end_date)
    (
        web,
        dark,
        web_df,
        web_source_df,
        web_attach,
        dark_web_df,
        web_only_df,
    ) = mention_metrics(idx, men_df)

    return (
        inc,
        creds,
        inc_src_df,
        inc_date_df,
        ce_inc_df,
        creds_attach,
        domains,
        utld,
        tld_df,
        dm_df,
        dm_samp,
        domains_attach,
        malware,
        uma,
        ma_act_df,
        ma_samp,
        ma_attach,
        vulns,
        iv_df,
        iv_act_df,
        iv_samp,
        iv_attach,
        vuln_ma_df,
        vuln_ma_df2,
        assets,
        web,
        dark,
        web_df,
        web_source_df,
        web_attach,
        dark_web_df,
        web_only_df,
    )
