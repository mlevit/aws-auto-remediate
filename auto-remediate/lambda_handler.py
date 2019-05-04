import boto3
import json
import logging
import os

from dynamodb_json import json_util as dynamodb_json

from config_rules import *
from sns_logging_handler import *

class Remediate:
    def __init__(self, logging, event):
        # parameters
        self.logging = logging
        self.event = event

        # variables
        self.settings = self.get_settings()

        # classes
        self.config = ConfigRules(self.logging)
        # self.security_hub = ConfigRules(self.logging)
        # self.custom = ConfigRules(self.logging)
    
    def remediate(self):
        for record in self.event.get('Records'):
            config_message = json.loads(record.get('Sns').get('Message'))
            config_rule_name = Remediate.get_config_rule_name(config_message)
            config_rule_compliance = Remediate.get_config_rule_compliance(config_message)
            
            if config_rule_compliance == 'NON_COMPLIANT':
                if 'auto-remediate' in config_rule_name:
                    # AWS Config Managed Rules
                    if 'access-keys-rotated' in config_rule_name:
                        self.config.access_keys_rotated(config_message)
                    elif 'restricted-ssh' in config_rule_name:
                        self.config.restricted_ssh(config_message)
                    elif 'rds-instance-public-access-check' in config_rule_name:
                        self.config.rds_instance_public_access_check(config_message)
                    else:
                        self.logging.warning("Auto Remediate has not been configured "
                                             "to remediate Config Rule '%s' "
                                             "with payload '%s'." % (config_rule_name, config_message))
                elif 'securityhub' in config_rule_name:
                    # AWS Security Hub Rules
                    self.logging.warning("Auto Remediate has not been configured "
                                         "to remediate Config Rule '%s' "
                                         "with payload '%s'." % (config_rule_name, config_message))
                else:
                    # Custom Config Rules
                    self.logging.warning("Auto Remediate has not been configured "
                                         "to remediate Config Rule '%s' "
                                         "with payload '%s'." % (config_rule_name, config_message))

    def intend_to_remediate(self, config_rule_name):
        return self.settings.get('rules').get(config_rule_name, {}).get('remediate', False)
    
    def get_settings(self):
        settings = {}
        try:
            for record in boto3.client('dynamodb').scan(TableName=os.environ['SETTINGSTABLE'])['Items']:
                record_json = dynamodb_json.loads(record, True)
                settings[record_json.get('key')] = record_json.get('value')
        except:
            self.logging.error("Could not read DynamoDB table '%s'." % os.environ['SETTINGSTABLE'])
        
        return settings
    
    @staticmethod
    def get_config_rule_name(record):
        return record.get('detail').get('configRuleName')
    
    @staticmethod
    def get_config_rule_compliance(record):
        return record.get('detail').get('newEvaluationResult').get('complianceType')


def lambda_handler(event, context):
    log = logging.getLogger()

    if log.handlers:
        for handler in log.handlers:
            log.removeHandler(handler)
    
    # change logging levels for boto and others
    logging.getLogger('boto3').setLevel(logging.ERROR)
    logging.getLogger('botocore').setLevel(logging.ERROR)
    logging.getLogger('urllib3').setLevel(logging.ERROR)
    
    # TODO test SNS logging
    # add SNS logger
    sns_logger = SNSLoggingHandler(os.environ.get('SNSLOGTOPIC'))
    sns_logger.setLevel(logging.INFO)
    log.addHandler(sns_logger)
    
    # set logging format
    logging.basicConfig(format="[%(levelname)s] %(message)s (%(filename)s, %(funcName)s(), line %(lineno)d)", 
                        level=os.environ.get('LOGLEVEL', 'WARNING').upper())

    # instantiate class
    remediate = Remediate(logging, event)

    # run functions
    remediate.remediate()