#!/usr/bin/env bash
# Get the zip file from Accessor by running:
# rsync -avrhP ubuntu@localhost:/home/ubuntu/db_backups/<latest dump file name>.zip <destination directory>
# Set path to pg dump and globals backup files. ex: /Users/user/Desktop/backups
path=

dropdb pe -h localhost -U postgres --if-exists

globalsql=$path/pedb_globals.sql
dumpsql=$path/pedb_dump.sql

psql -U postgres -h localhost -c "CREATE DATABASE pe;"

# rdsadmin database (even if empty) is required for the next script
psql -U postgres -h localhost -c "CREATE DATABASE rdsadmin;"

psql -U postgres -h localhost pe < "$globalsql"

pg_restore -U postgres -h localhost -d pe "$dumpsql"
