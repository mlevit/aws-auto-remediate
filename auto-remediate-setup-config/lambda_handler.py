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
        
        try:
            self.client = boto3.client('cloudformation')
        except:
            self.logging.error(str(sys.exc_info()))

        self.create_stacks()
    
    
    def create_stacks(self):
        """
        
        """
        existing_stacks = self.get_current_stacks()
        path = 'auto-remediate-setup-config/data'

        for file in os.listdir(path):
            if fnmatch.fnmatch(file, '*.json'):
                with open(os.path.join(path, file)) as stack:
                    stack_name = 'auto-remediate-%s' % file.replace('.json', '')
                    template_body = str(stack.read())
                    
                    if stack_name not in existing_stacks:
                        try:
                            self.client.create_stack(
                                StackName=stack_name,
                                TemplateBody=template_body,
                                OnFailure='DELETE',
                                EnableTerminationProtection=True)
                            
                            self.logging.info("Creating CloudFormation Stack '%s'." % stack_name)
                        except:
                            self.logging.error("Could not create CloudFormation Stack '%s'." % stack_name)
                            self.logging.error(str(sys.exc_info()))
                            continue
                    else:
                        self.logging.debug("Cloud Formation Stack '%s' already exists." % stack_name)
    

    def get_current_stacks(self):
        try:
            resources = self.client.list_stacks().get('StackSummaries')
        except:
            self.logging.error(str(sys.exc_info()))
            return None

        existing_stacks = []
        for resource in resources:
            existing_stacks.append(resource.get('StackName'))

        return existing_stacks


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