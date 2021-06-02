# Posture and Exposure (P&E) Reports #

[![GitHub Build Status](https://github.com/cisagov/pe-reports/workflows/build/badge.svg)](https://github.com/cisagov/pe-reports/actions)
[![Coverage Status](https://coveralls.io/repos/github/cisagov/pe-reports/badge.svg?branch=develop)](https://coveralls.io/github/cisagov/pe-reports?branch=develop)
[![Total alerts](https://img.shields.io/lgtm/alerts/g/cisagov/pe-reports.svg?logo=lgtm&logoWidth=18)](https://lgtm.com/projects/g/cisagov/pe-reports/alerts/)
[![Language grade: Python](https://img.shields.io/lgtm/grade/python/g/cisagov/pe-reports.svg?logo=lgtm&logoWidth=18)](https://lgtm.com/projects/g/cisagov/pe-reports/context:python)
[![Known Vulnerabilities](https://snyk.io/test/github/cisagov/pe-reports/develop/badge.svg)](https://snyk.io/test/github/cisagov/pe-reports)

This package is used to generate encrypted Posture and Exposure (P&E) PDF
reports using raw_data.xlsx files.

## Device Setup ##

Install LibreOffice for powerpoint to pdf conversion
<https://www.libreoffice.org/get-help/install-howto/macos/>.

Install python 3

(Optional) Setting up your Mac:
<https://github.com/cisagov/development-guide/blob/develop/dev_envs/mac-env-setup.md>

## Installation ##

Please see the
[Creating the Python virtual environment](CONTRIBUTING.md#creating-the-python-virtual-environment)
section of the [CONTRIBUTING](CONTRIBUTING.md) document for information about
setting up a Python virtual environment.

Required configurations:
*You must have access to the cyhy database
Install mongo-db-from-config (<https://github.com/cisagov/mongo-db-from-config>)
and follow the instructions to create the yaml file.
The report generator will read `/secrets/database_creds.yml` by default if no
yaml filepath is provided.

To generate a P&E report:

```console
python3 /pe-reports/src/pe_reports YYYY-MM-DD DATA_DIRECTORY OUTPUT_DIRECTORY [OPTIONS]
```

## Making Changes ##

To change any general report format/standard visuals edit
/src/data/shell/pe_shell.pptx

To make any style changes, edit /src/pe_reports/stylesheet.py

To change metrics, edit /src/pe_reports/report_metrics.py

To change page setups/graphs, edit /src/pe_reports/pages.py

## Contributing ##

We welcome contributions!  Please see [`CONTRIBUTING.md`](CONTRIBUTING.md) for
details.

## License ##

This project is in the worldwide [public domain](LICENSE).

This project is in the public domain within the United States, and
copyright and related rights in the work worldwide are waived through
the [CC0 1.0 Universal public domain
dedication](https://creativecommons.org/publicdomain/zero/1.0/).

All contributions to this project will be released under the CC0
dedication. By submitting a pull request, you are agreeing to comply
with this waiver of copyright interest.
