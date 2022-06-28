#!/usr/bin/env bash
set -o errexit
set -o nounset
set -o pipefail

# Set path to pg dump and globals backup files. ex: /Users/user/Desktop/backups
path=$PWD

dropdb pe -h localhost -U postgres --if-exists

globalsql=$path/pedb_globals.sql
dumpsql=$path/pedb_dump.sql

psql -U postgres -h localhost -c "CREATE DATABASE pe;"

# rdsadmin database (even if empty) is required for the next script
psql -U postgres -h localhost -c "CREATE DATABASE rdsadmin;"

psql -U postgres -h localhost pe < "$globalsql"

pg_restore -U postgres -h localhost -d pe "$dumpsql"
