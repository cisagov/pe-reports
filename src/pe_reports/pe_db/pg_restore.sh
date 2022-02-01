#!/usr/bin/env bash
# Set path to pg dump and globals backup files
path=

globalsql=$path/pgdb_globals.sql
dumpsql=$path/pg_dump.sql

psql -U postgres -c "CREATE DATABASE pe;"

# rdsadmin database (even if empty) is required for the next script
psql -U postgres -c "CREATE DATABASE rdsadmin;"

psql -U postgres pe < "$globalsql"

psql -U postgres pe < "$dumpsql"
