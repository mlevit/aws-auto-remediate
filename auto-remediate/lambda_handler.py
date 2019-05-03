import boto3
import datetime
import json
import logging
import os
import sys
import tempfile
import threading

class Remediate:
    def __init__(self, logging, event):
        self.logging = logging
        self.event = event

        for record in event.get('Records'):
            config_rule_name = self.get_config_rule_name(record)
            config_rule_compliance = self.get_config_rule_compliance(record)

            

    
    def get_config_rule_name(self, record):
        return record.get('Sns').get('Message').get('detail').get('configRuleName')
    

    def get_config_rule_compliance(self, record):
        return record.get('Sns').get('Message').get('detail').get('configRuleName').get('newEvaluationResult').get('complianceType')

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

    Remediate(logging, event)