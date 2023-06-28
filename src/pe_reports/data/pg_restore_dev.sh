#!/usr/bin/env bash
# Get the zip file from Accessor by running:
# rsync -avrhP ubuntu@localhost:/home/ubuntu/db_backups/<latest dump file name>.zip <destination directory>
# Set path to pg dump and globals backup files. ex: /Users/user/Desktop/backups
path=src/pe_reports/data/db_dev_schema.sql

dropdb pe_dev -h localhost -U postgres --if-exists

dropdb rdsadmin -h localhost -U postgres --if-exists

psql -U postgres -h localhost -c "CREATE DATABASE pe_dev;"

# rdsadmin database (even if empty) is required for the next script
psql -U postgres -h localhost -c "CREATE DATABASE rdsadmin;"


# connect to the database using psql
psql -U postgres -d pe_dev <<EOF

\i $path

