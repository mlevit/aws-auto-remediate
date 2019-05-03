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
        
        # instantiate classes with remidiation function
        self.managed = ManagedConfigRules(self.logging)
        # self.security_hub = ManagedConfigRules(self.logging)
        # self.custom = ManagedConfigRules(self.logging)

        self.parse_event(event)
    

    def parse_event(self, event):
        for record in event.get('Records'):
            config_rule_name = self.get_config_rule_name(record)
            config_rule_compliance = self.get_config_rule_compliance(record)

            if config_rule_compliance == 'NON_COMPLIANT':
                # TODO check if remidiation should occur
                remidiate = True
                if remidiate:
                    self.remidiate(config_rule_name, record)
                    
                    self.logging.info("Config Rule '%s' is non-compliant "
                                      "and has been sent for remidiation." % config_rule_name)
                else:
                    self.logging.info("Config Rule '%s' is non-compliant and has "
                                      "not been sent for remidiation based on user preferences." % config_rule_name)
            else:
                self.logging.info("Config Rule '%s' is now compliant." % config_rule_name)
    
    
    def get_config_rule_name(self, record):
        return record.get('Sns').get('Message').get('detail').get('configRuleName')
    

    def get_config_rule_compliance(self, record):
        return record.get('Sns').get('Message').get('detail').get('configRuleName').get('newEvaluationResult').get('complianceType')

    
    def remidiate(self, config_rule_name, record):
        remidation_function = self.get_remidiation_function(config_rule_name)

        if 'auto-remidiate' in config_rule_name:
            # managed config rules
            pass
        elif 'securityhub' in config_rule_name:
            # security hub rules
            pass
        else:
            # customer config rules
            pass
    

    def get_remidiation_function(self, config_rule_name):
        replacements = {'auto-remidiate-': '', 'securityhub-': '', '-': '_'}
        
        remidation_function = config_rule_name
        for old, new in replacements:
            remidation_function = remidation_function.replace(old, new)
        
        return remidation_function


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