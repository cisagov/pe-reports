#!/usr/bin/env bash
set -o errexit
set -o nounset
set -o pipefail

# Set path to save backup files
path=/home/ubuntu/db_backups
backup_folder=$path/backups_$(date +%m-%d-%Y)

globalsqlfile=$backup_folder/pedb_globals.sql
sqlfile=$backup_folder/pedb_dump.sql
errfile=$backup_folder/stderr.txt
zipfile=$path/pedb_dump_$(date +%m-%d-%Y).zip

# Create backup folder
mkdir -p "$backup_folder"

# Create globals backup
if pg_dumpall --globals-only --no-role-passwords --database "$PE_DB_NAME" --port "$PE_DB_PORT" --username "$PE_DB_USER" --host "$DATABASE_HOST" --no-password 2> "$errfile" > "$globalsqlfile"; then
  echo 'Globals dump created'
else
  echo 'Globals pg_dump return non-zero code'
  exit
fi

# Create backup
if pg_dump --dbname "$PE_DB_NAME" --port "$PE_DB_PORT" --username "$PE_DB_USER" --host "$DATABASE_HOST" --format custom --no-password 2> "$errfile" > "$sqlfile"; then
  echo 'PG dump created'
else
  echo 'pg_dump return non-zero code'
  exit
fi

# Zip folder
zip --recurse-paths "$zipfile" "$backup_folder"
