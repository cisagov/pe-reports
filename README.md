# Posture & Exposure Reports (P&E Reports) #

[![GitHub Build Status](https://github.com/cisagov/pe-reports/workflows/build/badge.svg)](https://github.com/cisagov/pe-reports/actions)
[![Coverage Status](https://coveralls.io/repos/github/cisagov/pe-reports/badge.svg?branch=develop)](https://coveralls.io/github/cisagov/pe-reports?branch=develop)
[![Total alerts](https://img.shields.io/lgtm/alerts/g/cisagov/pe-reports.svg?logo=lgtm&logoWidth=18)](https://lgtm.com/projects/g/cisagov/pe-reports/alerts/)
[![Language grade: Python](https://img.shields.io/lgtm/grade/python/g/cisagov/pe-reports.svg?logo=lgtm&logoWidth=18)](https://lgtm.com/projects/g/cisagov/pe-reports/context:python)

This package is used to generate and deliver CISA Posture & Exposure Reports
(P&E Reports). Reports are delivered by email and include an encrypted PDF
attachment with a series of embedded raw-data files of the collected materials.
The reports are delivered in a two step process. First the `pe_reports` module
collects the raw-data and creates the encrypted PDFs. The `pe_mailer` then
securely delivers the content.

Topics of interest include *Exposed Credentials, Domain Masquerading, Malware,
Inferred Vulnerabilities and the Dark Web*. The data collected for the reports
is gathered on the 1st and 15th of each month.

## Requirements ##

- [Python Environment](CONTRIBUTING.md#creating-the-python-virtual-environment)
- [cisagov MongoDB](https://github.com/cisagov/mongo-db-from-config)
- [cisagov AWS SES](https://github.com/cisagov/cool-dns-cyber.dhs.gov)

## Installation ##

- `git clone https://github.com/cisagov/pe-reports.git`

- `pip install -e .`

## Create P&E Reports ##

- Connect to [cisagov MongoDB](https://github.com/cisagov/mongo-db-from-config)

```consol
Usage:
  pe-reports [--pe-report-dir=DIRECTORY] [--db-creds-file=FILENAME] [--log-level=LEVEL]

Arguments:
  -r --pe-report-dir=DIRECTORY  Directory containing the pe-reports output.
  -c --db-creds-file=FILENAME   A YAML file containing the Cyber
                                Hygiene database credentials.
                                [default: /secrets/database_creds.yml]
Options:
  -h --help                     Show this message.
  -v --version                  Show version information.
  --log-level=LEVEL             If specified, then the log level will be set to
                                the specified value.  Valid values are "debug", "info",
                                "warning", "error", and "critical". [default: info]
```

## Deliver P&E Reports ##

- Connect to [cisagov MongoDB](https://github.com/cisagov/mongo-db-from-config)

- Load [AWS Profile](https://github.com/cisagov/cool-dns-cyber.dhs.gov)

```consol
Usage:
  pe-mailer [--pe-report-dir=DIRECTORY] [--db-creds-file=FILENAME] [--log-level=LEVEL]

Arguments:
  -r --pe-report-dir=DIRECTORY  Directory containing the pe-reports output.
  -c --db-creds-file=FILENAME   A YAML file containing the Cyber
                                Hygiene database credentials.
                                [default: /secrets/database_creds.yml]
Options:
  -h --help                     Show this message.
  -v --version                  Show version information.
  -s --summary-to=EMAILS        A comma-separated list of email addresses
                                to which the summary statistics should be
                                sent at the end of the run.  If not
                                specified then no summary will be sent.
  -t --test_emails=EMAILS       A comma-separated list of email addresses
                                to which to test email send process. If not
                                specified then no test will be sent.
  -l --log-level=LEVEL          If specified, then the log level will be set to
                                the specified value.  Valid values are "debug", "info",
                                "warning", "error", and "critical". [default: info]
```

## Contributing ##

We welcome contributions!  Please see [`CONTRIBUTING.md`](CONTRIBUTING.md) for details.

## License ##

This project is in the worldwide [public domain](LICENSE).

This project is in the public domain within the United States, and copyright
and related rights in the work worldwide are waived through the
[CC0 1.0 Universal public domain dedication](https://creativecommons.org/publicdomain/zero/1.0/).

All contributions to this project will be released under the CC0 dedication.
By submitting a pull request, you are agreeing to comply with this waiver
of copyright interest.
