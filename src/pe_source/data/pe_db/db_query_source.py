

def query_orgs_rev():
    """Query orgs in reverse."""
    conn = connect()
    sql = "SELECT * FROM organizations WHERE report_on is True ORDER BY organizations_uid DESC;"
    df = pd.read_sql_query(sql, conn)
    close(conn)
    return df


def getSubdomain(conn, domain):
    """Get subdomains given a domain from the databases."""
    cur = conn.cursor()
    sql = """SELECT * FROM sub_domains sd
        WHERE sd.sub_domain = %(domain)s"""
    cur.execute(sql, {"domain": domain})
    sub = cur.fetchone()
    cur.close()
    return sub


def addSubdomain(conn, domain, pe_org_uid):
    """Add a subdomain into the database."""
    root_domain = domain.split(".")[-2:]
    root_domain = ".".join(root_domain)
    cur = conn.cursor()
    cur.callproc(
        "insert_sub_domain", (domain, pe_org_uid, "findomain", root_domain, None)
    )
    LOGGER.info("Success adding domain %s to subdomains table.", domain)


def getDataSource(conn, source):
    """Get datasource information from a database."""
    cur = conn.cursor()
    sql = """SELECT * FROM data_source WHERE name=%(s)s"""
    cur.execute(sql, {"s": source})
    source = cur.fetchone()
    cur.close()
    return source


def org_root_domains(conn, org_uid):
    """Get root domains from database given the org_uid."""
    sql = """
        select * from root_domains rd
        where rd.organizations_uid = %(org_id)s;
    """
    df = pd.read_sql_query(sql, conn, params={"org_id": org_uid})
    return df


def insert_intelx_breaches(df):
    """Insert IntelX breach data."""
    conn = connect()
    table = "credential_breaches"
    # Create a list of tuples from the dataframe values
    tuples = [tuple(x) for x in df.to_numpy()]
    # Comma-separated dataframe columns
    cols = ",".join(list(df.columns))
    # SQL query to execute
    query = """INSERT INTO {}({}) VALUES %s
    ON CONFLICT (breach_name) DO UPDATE SET
    password_included = EXCLUDED.password_included;"""
    cursor = conn.cursor()
    try:
        extras.execute_values(
            cursor,
            query.format(
                table,
                cols,
            ),
            tuples,
        )
        conn.commit()
        LOGGER.info("Successfully inserted/updated IntelX breaches into PE database.")
    except (Exception, psycopg2.DatabaseError) as error:
        LOGGER.info(error)
        conn.rollback()
    cursor.close()


def get_intelx_breaches(source_uid):
    """Get IntelX credential breaches."""
    conn = connect()
    try:
        cur = conn.cursor()
        sql = """SELECT breach_name, credential_breaches_uid FROM credential_breaches where data_source_uid = %s"""
        cur.execute(sql, [source_uid])
        all_breaches = cur.fetchall()
        cur.close()
        return all_breaches
    except (Exception, psycopg2.DatabaseError) as error:
        LOGGER.error("There was a problem with your database query %s", error)
    finally:
        if conn is not None:
            close(conn)


def insert_intelx_credentials(df):
    """Insert IntelX credential data."""
    conn = connect()
    table = "credential_exposures"
    # Create a list of tuples from the dataframe values
    tuples = [tuple(x) for x in df.to_numpy()]
    # Comma-separated dataframe columns
    cols = ",".join(list(df.columns))
    # SQL query to execute
    query = """INSERT INTO {}({}) VALUES %s
    ON CONFLICT (breach_name, email) DO UPDATE SET
    modified_date = EXCLUDED.modified_date;"""
    cursor = conn.cursor()
    try:
        extras.execute_values(
            cursor,
            query.format(
                table,
                cols,
            ),
            tuples,
        )
        conn.commit()
        LOGGER.info(
            "Successfully inserted/updated exposed IntelX credentials into PE database."
        )
    except (Exception, psycopg2.DatabaseError) as error:
        LOGGER.info(error)
        conn.rollback()
    cursor.close()
