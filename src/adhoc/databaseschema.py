finding = {
    'finding_uid': uid,
    'finding_type': findingType,
    'org_id': idStr,
    'name': name,
    'owasp_category': owasp_category,
    'type': findingType,
    'severity': severity,
    'times_detected': timesDetected,
    'base_score': cvssV3['base'],
    'temporal_Score': cvssV3['temporal'],
    'status': 'ACTIVE',
    'last_detected': lastDetected,
    'first_detected': firstDetected,
    'date': now
}

sql_table2 = """
    CREATE TABLE IF NOT EXISTS was_customers
    (
        org_id varchar UNIQUE,
        webapp_count int,
        webapp_active_vuln_count int,
        date date
    )
"""

sql = """
    CREATE TABLE IF NOT EXISTS findings 
    (
        finding_uid uuid UNIQUE,
        finding_type varchar,
        org_id varchar,
        name varchar,
        owasp_category varchar,
        type varchar, 
        severity varchar, 
        times_detected int, 
        base_score float8, 
        temporal_score float8, 
        status varchar, 
        last_detected date, 
        first_detected date,
        date date
    );
"""

insert = """
    INSERT INTO findings (finding_uid, finding_type, org_id, name, owasp_category, type, severity, times_detected, base_score, temporal_score, status, last_detected, first_detected, date)
"""
