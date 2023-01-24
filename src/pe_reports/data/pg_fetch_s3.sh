#!/usr/bin/env bash

path=~/Desktop/db_backups
profile=cool-dns-sesmanagesuppressionlist-cyber.dhs.gov

latest_backup=$(aws s3 ls s3://cisa-crossfeed-pe-db-backups/ \
--profile $profile \
--recursive \
--human-readable \
--summarize | awk '{print $5}' | awk -F '/' '/\// {print $1}' | sort -u | tail -n 1) &&

aws s3 cp \
   --recursive \
   s3://cisa-crossfeed-pe-db-backups/$latest_backup/ \
   $path/ \
   --profile $profile

