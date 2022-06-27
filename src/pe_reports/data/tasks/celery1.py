from celery import Celery

# app = Celery('tasks', backend='rpc://')


app = Celery('pe_reports.data.tasks.tasks',
             # broker='amqp://',
             backend='rpc://',
             include=['pe_reports.data.tasks.tasks'])

app.config_from_object('pe_reports.data.tasks.celeryconfig')

# Optional configuration, see the application user guide.
app.conf.update(
    result_expires=3600,
)

if __name__ == '__main__':
    app.start()
