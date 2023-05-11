"""Name Update.

Usage:
    name_update.py <old-name> <new-name>
    name_update.py (-h | --help)
    name_update.py --version

Options:
    -h --help   Show this screen.
    --version   Show version.
"""

# Third-Party Libraries
from data.run import close, connect
from docopt import docopt


def main():
    """Rename an organization in the database."""
    args = docopt(__doc__, version="v0.0.1")
    conn = connect("")
    cursor = conn.cursor()
    cursor.execute(
        "UPDATE ORGANIZATIONS set NAME = (%s) WHERE NAME = (%s)",
        (args["<new-name>"], args["<old-name>"]),
    )
    print("%s records updated" % cursor.rowcount)
    conn.commit()
    close(conn)


if __name__ == "__main__":
    main()
