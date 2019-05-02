import boto3
import datetime
import fnmatch
import json
import logging
import os
import sys
import tempfile
import threading


class SetupConfig:
    def __init__(self, logging):
        self.logging = logging

        self.create_stacks()
    
    
    def create_stacks(self):
        """
        
        """

        client = boto3.client('cloudformation')
        path = 'auto-remediate-setup-config/data'

        for file in os.listdir(path):
            if fnmatch.fnmatch(file, '*.json'):
                with open(os.path.join(path, file)) as stack:
                    stack_name = file.replace('.json', '')
                    template_body = str(stack.read())
                    
                    # @todo Check if stack already exists
                    # @body Before trying to create a new stack, check if the stack already exists, if stack is in failed state then remove and re-create.
                    try:
                        print(client.create_stack(
                            StackName=stack_name,
                            TemplateBody=template_body))
                        
                        self.logging.info("Creating CloudFormation Stack '%s'." % stack_name)
                    except:
                        self.logging.error("Could not create CloudFormation Stack '%s'." % stack_name)
                        self.logging.error(str(sys.exc_info()))
                        continue


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

    SetupConfig(logging)