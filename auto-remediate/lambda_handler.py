import boto3
import json
import logging
import os
import sys

from dynamodb_json import json_util as dynamodb_json

from config_rules import *
from security_hub_rules import *
from custom_rules import *
from sns_logging_handler import *

class Remediate:
    def __init__(self, logging, event):
        # parameters
        self.logging = logging
        self.event = event
        
        # event payload
        self.logging.debug(f"Event payload: {self.event}")

        # variables
        self.settings = self.get_settings()

        # classes
        self.config = ConfigRules(self.logging)
        self.security_hub = SecurityHubRules(self.logging)
        self.custom = CustomRules(self.logging)
    
    def remediate(self):
        for record in self.event.get('Records'):
            remediation = True
            try_count = record.get('messageAttributes', {}).get('try_count', {}).get('stringValue', '0')
            config_message = json.loads(record.get('body'))
            config_rule_name = Remediate.get_config_rule_name(config_message)
            config_rule_compliance = Remediate.get_config_rule_compliance(config_message)
            config_rule_resource_id = Remediate.get_config_rule_resource_id(config_message)
            
            if config_rule_compliance == 'NON_COMPLIANT':
                if self.intend_to_remediate(config_rule_name):
                    if 'auto-remediate' in config_rule_name:
                        # AWS Config Managed Rules
                        if 'rds-instance-public-access-check' in config_rule_name:
                            remediation = self.config.rds_instance_public_access_check(config_rule_resource_id)
                        else:
                            self.logging.warning(
                                f"No remediation available for Config Rule "
                                f"'{config_rule_name}' with payload '{config_message}'.")
                    elif 'securityhub' in config_rule_name:
                        # AWS Security Hub Rules
                        if 'iam-password-policy' in config_rule_name:
                            remediation = self.security_hub.iam_password_policy(config_rule_resource_id)
                        elif 'iam-user-unused-credentials-check' in config_rule_name:
                            remediation = self.security_hub.iam_user_unused_credentials_check(config_rule_resource_id)
                        elif 'restricted-rdp' in config_rule_name:
                            remediation = self.security_hub.restricted_rdp(config_rule_resource_id)
                        elif 'restricted-ssh' in config_rule_name:
                            remediation = self.security_hub.restricted_ssh(config_rule_resource_id)
                        elif 's3-bucket-public-read-prohibited' in config_rule_name:
                            remediation = self.security_hub.s3_bucket_public_read_prohibited(config_rule_resource_id)
                        elif 's3-bucket-public-write-prohibited' in config_rule_name:
                            remediation = self.security_hub.s3_bucket_public_write_prohibited(config_rule_resource_id)
                        else:
                            self.logging.warning(
                                f"No remediation available for Config Rule "
                                f"'{config_rule_name}' with payload '{config_message}'.")
                    else:
                        # Custom Config Rules
                        self.logging.warning(
                            f"No remediation available for Config Rule "
                            f"'{config_rule_name}' with payload '{config_message}'.")
                else:
                    self.logging.info(f"Config Rule '{config_rule_name}' was not remediated based on user preferences.")
            else:
                self.logging.info(
                    f"Resource '{config_rule_resource_id}' is compliant for Config Rule '{config_rule_name}'.")
            
            # if remediation was not successful, send message to DLQ
            if not remediation:
                self.send_to_dlq(config_message, try_count)  

    def intend_to_remediate(self, config_rule_name):
        return self.settings.get('rules').get(config_rule_name, {}).get('remediate', True)
    
    def get_settings(self):
        settings = {}
        try:
            for record in boto3.client('dynamodb').scan(TableName=os.environ['SETTINGSTABLE'])['Items']:
                record_json = dynamodb_json.loads(record, True)
                settings[record_json.get('key')] = record_json.get('value')
        except:
            self.logging.error(f"Could not read DynamoDB table '{os.environ['SETTINGSTABLE']}'.")
            self.logging.error(sys.exc_info()[1])
        
        return settings
    
    def send_to_dlq(self, message, try_count):
        """
        Sends a message to the DLQ
        """
        client = boto3.client('sqs')
        
        try_count = int(try_count) + 1
        if try_count < int(os.environ.get('RETRYCOUNT', 3)):
            try:
                client.send_message(
                    QueueUrl=self.get_queue_url(),
                    MessageBody=json.dumps(message),
                    MessageAttributes={
                        'try_count': {
                            'StringValue': str(try_count),
                            'DataType': 'Number'
                            }
                        }
                    )
                
                self.logging.debug(f"Remediation failed. Payload has been sent to DLQ '{os.environ.get('DLQ')}'.")
            except:
                self.logging.error(f"Could not send payload to DLQ '{os.environ.get('DLQ')}'.")
                self.logging.error(sys.exc_info()[1])
        else:
            self.logging.warning(
                f"Could not remediate Config change within an acceptable number of retries for payload '{message}'.")

    def get_queue_url(self):
        """
        Retrieves the SQS Queue URL from the SQS Queue Name.
        """
        client = boto3.client('sqs')
        
        try:
            response = client.get_queue_url(QueueName=os.environ.get('DLQ'))
            return response.get('QueueUrl')
        except:
            self.logging.error(f"Could not retrieve SQS Queue URL for SQS Queue '{os.environ.get('DLQ')}'.")
            self.logging.error(sys.exc_info()[1])
    
    @staticmethod
    def get_config_rule_name(record):
        return record.get('detail').get('configRuleName')
    
    @staticmethod
    def get_config_rule_compliance(record):
        return record.get('detail').get('newEvaluationResult').get('complianceType')

    @staticmethod
    def get_config_rule_resource_id(record):
        return record.get('detail').get('resourceId')


def lambda_handler(event, context):
    loggger = logging.getLogger()

    if loggger.handlers:
        for handler in loggger.handlers:
            loggger.removeHandler(handler)
    
    # change logging levels for boto and others
    logging.getLogger('boto3').setLevel(logging.ERROR)
    logging.getLogger('botocore').setLevel(logging.ERROR)
    logging.getLogger('urllib3').setLevel(logging.ERROR)
    
    # set logging format
    logging.basicConfig(format="[%(levelname)s] %(message)s (%(filename)s, %(funcName)s(), line %(lineno)d)",
                        level=os.environ.get('LOGLEVEL', 'WARNING'))
    
    # add SNS logger
    # sns_logger = SNSLoggingHandler(os.environ.get('LOGTOPIC'))
    # sns_logger.setLevel(logging.INFO)
    # loggger.addHandler(sns_logger)
    
    # instantiate class
    remediate = Remediate(logging, event)

    # run functions
    remediate.remediate()