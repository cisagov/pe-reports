"""Celery configuration."""
broker_url = "amqp://admin:guest1@localhost:5672"
task_serializer = "json"
result_serializer = "json"
accept_content = ["json"]
result_backend = "rpc://"
result_persistent = False
imports = "pe_reports.data.tasks.tasks"
