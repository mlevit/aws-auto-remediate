import boto3
import json
import logging
import os
import sys

from dynamodb_json import json_util as dynamodb_json

from config_rules import *
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
        # self.security_hub = ConfigRules(self.logging)
        # self.custom = ConfigRules(self.logging)
    
    def remediate(self):
        for record in self.event.get('Records'):
            remediation = True
            config_message = json.loads(record.get('body'))
            config_rule_name = Remediate.get_config_rule_name(config_message)
            config_rule_compliance = Remediate.get_config_rule_compliance(config_message)
            
            if config_rule_compliance == 'NON_COMPLIANT':
                if self.intend_to_remediate(config_rule_name):
                    if 'auto-remediate' in config_rule_name:
                        # AWS Config Managed Rules
                        if 'access-keys-rotated' in config_rule_name:
                            remediation = self.config.access_keys_rotated(config_message)
                        elif 'restricted-ssh' in config_rule_name:
                            remediation =  self.config.restricted_ssh(config_message)
                        elif 'rds-instance-public-access-check' in config_rule_name:
                            remediation =  self.config.rds_instance_public_access_check(config_message)
                        else:
                            self.logging.warning("No remediation available for Config Rule '%s' "
                                                 "with payload '%s'." % (config_rule_name, config_message))
                    elif 'securityhub' in config_rule_name:
                        # AWS Security Hub Rules
                        self.logging.warning("No remediation available for Config Rule '%s' "
                                             "with payload '%s'." % (config_rule_name, config_message))
                    else:
                        # Custom Config Rules
                        self.logging.warning("No remediation available for Config Rule '%s' "
                                             "with payload '%s'." % (config_rule_name, config_message))
                else:
                    self.logging.info("Config Rule '%s' was not remediated "
                                      "based on user preferences." % config_rule_name)
            else:
                pass
            
            if not remediation:
                self.send_to_dlq()
                

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
    
    def send_to_dlq(self):
        """
        Sends a message to the DLQ
        """
        client = boto3.client('sqs')
        
        try:
            client.send_message(
                QueueUrl=self.get_queue_url(),
                MessageBody=str(self.event))
            
            self.logging.debug("Remediation failed. Payload has been sent to DLQ '%s'." % os.environ.get('DLQ'))
        except:
            self.logging.error("Could not send payload to DLQ '%s'." % os.environ.get('DLQ'))
            self.logging.error(sys.exc_info()[1])

    def get_queue_url(self):
        """
        Retrieves the SQS Queue URL from the SQS Queue Name
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