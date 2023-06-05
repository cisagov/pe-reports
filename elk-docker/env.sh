#!/bin/bash
# This is a Bash script to retrieve parameters from AWS Systems Manager (SSM) Parameter Store and store them in a .env file.

# Get the Stack Version parameter and append it to the .env file.
STACK_VERSION=$(aws ssm get-parameter --name /ELK-Test/STACK-VERSION --query 'Parameter.Value' --output text)
echo "STACK_VERSION=${STACK_VERSION}" >> .env

# Get the Elastic Password parameter, decrypt it, and append it to the .env file.
ELASTIC_PASSWORD=$(aws ssm get-parameter --name /ELK-Test/ELASTIC_PASSWORD --with-decryption --query 'Parameter.Value' --output text)
echo "ELASTIC_PASSWORD=${ELASTIC_PASSWORD}" >> .env

# Get the Kibana Password parameter, decrypt it, and append it to the .env file.
KIBANA_PASSWORD=$(aws ssm get-parameter --name /ELK-Test/KIBANA_PASSWORD --with-decryption --query 'Parameter.Value' --output text)
echo "KIBANA_PASSWORD=${KIBANA_PASSWORD}" >> .env

# Get the Cluster Name parameter, decrypt it, and append it to the .env file.
CLUSTER_NAME=$(aws ssm get-parameter --name /ELK-Test/CLUSTER_NAME --with-decryption --query 'Parameter.Value' --output text)
echo "CLUSTER_NAME=${CLUSTER_NAME}" >> .env

# Get the License parameter, decrypt it, and append it to the .env file.
LICENSE=$(aws ssm get-parameter --name /ELK-Test/LICENSE --with-decryption --query 'Parameter.Value' --output text)
echo "LICENSE=${LICENSE}" >> .env

# Get the Elasticsearch Port parameter, decrypt it, and append it to the .env file.
ES_PORT=$(aws ssm get-parameter --name /ELK-Test/ES_PORT --with-decryption --query 'Parameter.Value' --output text)
echo "ES_PORT=${ES_PORT}" >> .env

# Get the Kibana Port parameter, decrypt it, and append it to the .env file.
KIBANA_PORT=$(aws ssm get-parameter --name /ELK-Test/KIBANA_PORT --with-decryption --query 'Parameter.Value' --output text)
echo "KIBANA_PORT=${KIBANA_PORT}" >> .env

# Get the APM Port parameter, decrypt it, and append it to the .env file.
APM_PORT=$(aws ssm get-parameter --name /ELK-Test/APM_PORT --with-decryption --query 'Parameter.Value' --output text)
echo "APM_PORT=${APM_PORT}" >> .env

# Get the Logstash Pipeline Path parameter, decrypt it, and append it to the .env file.
LOGSTASH_PIPELINE_PATH=$(aws ssm get-parameter --name /ELK-Test/LOGSTASH_PIPELINE_PATH --with-decryption --query 'Parameter.Value' --output text)
echo "LOGSTASH_PIPELINE_PATH=.${LOGSTASH_PIPELINE_PATH}" >> .env

# Get the Memory Limit parameter, decrypt it, and append it to the .env file.
MEM_LIMIT=$(aws ssm get-parameter --name /ELK-Test/MEM_LIMIT --with-decryption --query 'Parameter.Value' --output text)
echo "MEM_LIMIT=${MEM_LIMIT}" >> .env

# Get the Kibana Username parameter, decrypt it, and append it to the .env file.
KIBANA_USERNAME=$(aws ssm get-parameter --name /ELK-Test/KIBANA_USERNAME --with-decryption --query 'Parameter.Value' --output text)
echo "KIBANA_USERNAME=${KIBANA_USERNAME}" >> .env

# Get the Elastic Username parameter, decrypt it, and append it to the .env file.
ELASTIC_USERNAME=$(aws ssm get-parameter --name /ELK-Test/ELASTIC_USERNAME --with-decryption --query 'Parameter.Value' --output text)
echo "ELASTIC_USERNAME=${ELASTIC_USERNAME}" >> .env

# Get the Logstash Port parameter, decrypt it, and append it to the .env file.
LOGSTASH_PORT=$(aws ssm get-parameter --name /ELK-Test/LOGSTASH_PORT --with-decryption --query 'Parameter.Value' --output text)
echo "LOGSTASH_PORT=${LOGSTASH_PORT}" >> .env

# Get the Crypto Password parameter, decrypt it, and append it to the .env file.
CRYPTO_PASSWORD=$(aws ssm get-parameter --name /ELK-Test/CRYPTO_PASSWORD --with-decryption --query 'Parameter.Value' --output text)
echo "CRYPTO_PASSWORD=${CRYPTO_PASSWORD}" >> .env
