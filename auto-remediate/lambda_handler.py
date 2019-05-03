import boto3
import json
import logging
import os
import sys

from dynamodb_json import json_util as dynamodb_json

from config_rules import *

class Remediate:
    def __init__(self, logging, event):
        self.logging = logging
        self.settings = self.get_settings()

        self.config = ConfigRules(self.logging)
        # self.security_hub = ConfigRules(self.logging)
        # self.custom = ConfigRules(self.logging)

        self.remediate(event)

    
    def remediate(self, event):
        for record in event.get('Records'):
            config_message = json.loads(record.get('Sns').get('Message'))
            
            config_rule_name = self.get_config_rule_name(config_message)
            config_rule_compliance = self.get_config_rule_compliance(config_message)
            
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
                                             "to remediate Config Rule '%s'." % config_rule_name)
                        self.logging.debug("Payload: %s" % config_message)
                elif 'securityhub' in config_rule_name:
                    # AWS Security Hub Rules
                    self.logging.warning("Auto Remediate has not been configured "
                                         "to remediate Config Rule '%s'." % config_rule_name)
                    self.logging.debug("Payload: %s" % config_message)
                else:
                    # Custom Config Rules
                    pass
    

    def get_settings(self):
        settings = {}
        try:
            for record in boto3.client('dynamodb').scan(TableName=os.environ['SETTINGSTABLE'])['Items']:
                record_json = dynamodb_json.loads(record, True)
                settings[record_json.get('key')] = record_json.get('value')
        except:
            self.logging.error("Could not read DynamoDB table '%s'." % os.environ['SETTINGSTABLE'])
        
        return settings
    
    
    def get_config_rule_name(self, record):
        return record.get('detail').get('configRuleName')
    

    def get_config_rule_compliance(self, record):
        return record.get('detail').get('newEvaluationResult').get('complianceType')
    

    def intend_to_remediate(self, config_rule_name):
        return self.settings.get('rules').get(config_rule_name, {}).get('remediate', False)


def lambda_handler(event, context):
    # enable logging
    root = logging.getLogger()

    if root.handlers:
        for handler in root.handlers:
            root.removeHandler(handler)

    logging.getLogger('boto3').setLevel(logging.ERROR)
    logging.getLogger('botocore').setLevel(logging.ERROR)
    logging.getLogger('urllib3').setLevel(logging.ERROR)
    logging.basicConfig(format="[%(levelname)s] %(message)s (%(filename)s, %(funcName)s(), line %(lineno)d)", level=os.environ.get('LOGLEVEL', 'WARNING').upper())

    # TODO logs should also be sent to an SNS Topic

    Remediate(logging, event)