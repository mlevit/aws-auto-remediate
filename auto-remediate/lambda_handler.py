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
        self.logging.debug("Event payload: %s" % self.event)

        # variables
        self.settings = self.get_settings()

        # classes
        self.config = ConfigRules(self.logging)
        self.security_hub = SecurityHubRules(self.logging)
        self.custom = CustomRules(self.logging)
    
    def remediate(self):
        for record in self.event.get('Records'):
            remediation = True
            config_message = json.loads(record.get('body'))
            try_count = record.get('messageAttributes', {}).get('try_count', {}).get('stringValue', '0')
            config_rule_name = Remediate.get_config_rule_name(config_message)
            config_rule_compliance = Remediate.get_config_rule_compliance(config_message)
            
            if config_rule_compliance == 'NON_COMPLIANT':
                if self.intend_to_remediate(config_rule_name):
                    if 'auto-remediate' in config_rule_name:
                        # AWS Config Managed Rules
                        if 'rds-instance-public-access-check' in config_rule_name:
                            remediation = self.config.rds_instance_public_access_check(config_message)
                        else:
                            self.logging.warning("No remediation available for Config Rule '%s' "
                                                 "with payload '%s'." % (config_rule_name, config_message))
                    elif 'securityhub' in config_rule_name:
                        # AWS Security Hub Rules
                        if 'restricted-rdp' in config_rule_name:
                            remediation = self.config.restricted_rdp(config_message)
                        elif 'restricted-ssh' in config_rule_name:
                            remediation = self.config.restricted_ssh(config_message)
                        else:
                            self.logging.warning("No remediation available for Config Rule '%s' "
                                                 "with payload '%s'." % (config_rule_name, config_message))
                    else:
                        # Custom Config Rules
                        self.logging.warning("No remediation available for Config Rule '%s' "
                                             "with payload '%s'." % (config_rule_name, config_message))
                else:
                    self.logging.info("Config Rule '%s' was not remediated "
                                      "based on user preferences." % config_rule_name)
            
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
            self.logging.error("Could not read DynamoDB table '%s'." % os.environ['SETTINGSTABLE'])
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
                
                self.logging.debug("Remediation failed. Payload has been sent to DLQ '%s'." % os.environ.get('DLQ'))
            except:
                self.logging.error("Could not send payload to DLQ '%s'." % os.environ.get('DLQ'))
                self.logging.error(sys.exc_info()[1])
        else:
            self.logging.warning("Could not remediate Config change within an "
                                 "acceptable number of retries for payload '%s'." % message)

    def get_queue_url(self):
        """
        Retrieves the SQS Queue URL from the SQS Queue Name.
        """
        client = boto3.client('sqs')
        
        try:
            response = client.get_queue_url(QueueName=os.environ.get('DLQ'))
            return response.get('QueueUrl')
        except:
            self.logging.error("Could not retrieve SQS Queue URL "
                               "for SQS Queue '%s'." % os.environ.get('DLQ'))
            self.logging.error(sys.exc_info()[1])
    
    @staticmethod
    def get_config_rule_name(record):
        return record.get('detail').get('configRuleName')
    
    @staticmethod
    def get_config_rule_compliance(record):
        return record.get('detail').get('newEvaluationResult').get('complianceType')


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
    sns_logger = SNSLoggingHandler(os.environ.get('LOGTOPIC'))
    sns_logger.setLevel(logging.INFO)
    loggger.addHandler(sns_logger)
    
    # instantiate class
    remediate = Remediate(logging, event)

    # run functions
    remediate.remediate()