#!/usr/bin/env bash
set -o errexit
set -o nounset
set -o pipefail

# Set path to pg dump and globals backup files. ex: /Users/user/Desktop/backups
path=$PWD

dropdb pe ---host localhost --username postgres --if-exists

globalsql=$path/pedb_globals.sql
dumpsql=$path/pedb_dump.sql

psql --username postgres --host localhost --command "CREATE DATABASE pe;"

# rdsadmin database (even if empty) is required for the next script
psql --username postgres --host localhost --command "CREATE DATABASE rdsadmin;"

psql --username postgres --host localhost pe < "$globalsql"

pg_restore --username postgres --host localhost --dbname pe "$dumpsql"
