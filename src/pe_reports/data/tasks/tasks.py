"""All task functions to gather source data for reports."""

# Third-Party Libraries


# cisagov Libraries
from pe_reports.data.tasks.celery1 import app


@app.task(name="sumNumbers")
def add(x, y):
    """Add two numbers together"""
    return x + y


# @app.on_after_finalize
# def schedule_periodic_task(sender, **kwargs):
#     sender.add_periodic_task(15.0, add(4, 4))


"""Data gathering"
    Shodan?
    CSG api call times
    """
