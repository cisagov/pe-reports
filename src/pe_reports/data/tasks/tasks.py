from pe_reports.data.tasks.celery1 import app


# app = Celery('tasks', backend='rpc://')
# app.config_from_object('celeryconfig')

@app.task(name='sumNumbers')
def add(x, y):

    return x + y
