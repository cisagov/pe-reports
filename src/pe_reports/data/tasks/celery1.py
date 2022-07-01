"""Create Celery objects."""


# Third-Party Libraries
from celery import Celery

# app = Celery('tasks', backend='rpc://')


app = Celery(
    # "pe_reports.data.tasks.tasks",
    # broker='amqp://admin:guest1@localhost:5672',
    backend="rpc://",
    include=["pe_reports.data.tasks.tasks"],
)

app.config_from_object("pe_reports.data.tasks.celeryconfig")


# Optional configuration, see the application user guide.
app.conf.update(
    result_expires=3600,
)

# Import all tasks that are found
app.autodiscover_tasks()

app.conf.beat_schedule = {
    "add-every-30-seconds": {"task": "sumNumbers", "schedule": 5.0, "args": (4, 4)}
}

if __name__ == "__main__":
    app.start()
