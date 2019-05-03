import boto3
import datetime
import json
import logging
import os
import sys
import tempfile
import threading

from managed_config_rules import *

class Remediate:
    def __init__(self, logging, event):
        self.logging = logging
        
        # instantiate classes with remediation function
        self.config = ConfigManagedRules(self.logging)
        # self.security_hub = ConfigManagedRules(self.logging)
        # self.custom = ConfigManagedRules(self.logging)

        self.parse_event(event)
    

    def parse_event(self, event):
        for record in event.get('Records'):
            config_rule_name = self.get_config_rule_name(record)
            config_rule_compliance = self.get_config_rule_compliance(record)

            if config_rule_compliance == 'NON_COMPLIANT':
                # TODO check if remediation should occur
                remediate = True
                if remediate:
                    self.remediate(config_rule_name, record)
                    
                    self.logging.info("Config Rule '%s' is non-compliant "
                                      "and has been sent for remediation." % config_rule_name)
                else:
                    self.logging.info("Config Rule '%s' is non-compliant and has "
                                      "not been sent for remediation based on user preferences." % config_rule_name)
            else:
                self.logging.info("Config Rule '%s' is now compliant." % config_rule_name)
    
    
    def get_config_rule_name(self, record):
        return record.get('Sns').get('Message').get('detail').get('configRuleName')
    

    def get_config_rule_compliance(self, record):
        return record.get('Sns').get('Message').get('detail').get('configRuleName').get('newEvaluationResult').get('complianceType')

    
    def remediate(self, config_rule_name, record):
        if 'auto-remediate' in config_rule_name:
            # AWS Config Managed Rules
            if 'access-keys-rotated' in config_rule_name:
                self.config.access_keys_rotated(record)
            elif 'restricted-ssh' in config_rule_name:
                self.config.restricted_ssh(record)
            else:
                self.logging.warning("Auto Remediate has not been configured "
                                     "to remediate Config Rule '%s'." % config_rule_name)
        elif 'securityhub' in config_rule_name:
            # AWS Security Hub Rules
            self.logging.warning("Auto Remediate has not been configured "
                                 "to remediate Config Rule '%s'." % config_rule_name)
        else:
            # Custom Config Rules
            pass


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