# BROKER_TRANSPORT = 'amqp'
# BROKER_USER = 'admin'
# BROKER_PASSWORD = 'guest1'
# BROKER_HOST = 'localhost'

broker_url = 'amqp://admin:guest1@localhost:5672'
result_backend = 'rpc://'
result_persistent = False



imports = ('pe_reports.data.tasks.tasks')
