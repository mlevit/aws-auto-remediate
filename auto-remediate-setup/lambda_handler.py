import boto3
import datetime
import fnmatch
import json
import logging
import os
import sys

class Setup:
    def __init__(self, logging):
        # parameters
        self.logging = logging
        
        # variables
        self.client = boto3.client('cloudformation')
    
    
    def create_stacks(self, stack_sub_dir):
        """
        Parse a directory and create the CloudFormation Stacks
        it contains.
        """

        existing_stacks = self.get_current_stacks()
        path = 'auto-remediate-setup-config/data/%s' % stack_sub_dir
        
        print(existing_stacks)

        for file in os.listdir(path):
            if fnmatch.fnmatch(file, '*.json'):
                stack_name = file.replace('.json', '')
                template_body = None
                
                with open(os.path.join(path, file)) as stack:
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
        """
        Retrieve a list of all CloudFormation Stacks
        currently deployed your AWS accont and region.
        """
        
        try:
            resources = self.client.list_stacks().get('StackSummaries')
        except:
            self.logging.error(str(sys.exc_info()))
            return None

        existing_stacks = []
        for resource in resources:
            if resource.get('StackStatus') not in ('DELETE_COMPLETE'):
                existing_stacks.append(resource.get('StackName'))

        return existing_stacks
    

    def setup_dynamodb(self):
        """
        Inserts all the default settings into a DynamoDB table.
        """

        try:
            client = boto3.client('dynamodb')
            settings_data = open('auto-remediate-setup-config/data/auto-remediate-settings.json')
            settings_json = json.loads(settings_data.read())

            update_settings = False
            
            # get current settings version
            current_version = client.get_item(
                TableName=os.environ['SETTINGSTABLE'],
                Key={'key': {'S': 'version'}},
                ConsistentRead=True)
            
            # get new settings version
            new_version = float(settings_json[0].get('value', {}).get('N', 0.0))
            
            # check if settings exist and if they're older than current settings
            if 'Item' in current_version:
                current_version = float(current_version.get('Item').get('value').get('N'))
                if current_version < new_version:
                    update_settings = True
                    self.logging.info("Existing settings with version %s are being updated to version %s in DynamoDB Table '%s'." % (str(current_version), str(new_version), os.environ['SETTINGSTABLE']))
                else:
                    self.logging.debug("Existing settings are at the lastest version %s in DynamoDB Table '%s'." % (str(current_version), os.environ['SETTINGSTABLE']))
            else:
                update_settings = True
                self.logging.info("Settings are being inserted into DynamoDB Table '%s' for the first time." % os.environ['SETTINGSTABLE'])

            if update_settings:
                for setting in settings_json:
                    try:
                        client.put_item(
                            TableName=os.environ['SETTINGSTABLE'],
                            Item=setting)
                    except:
                        self.logging.error(str(sys.exc_info()))
                        continue
        
            settings_data.close()
        except:
            self.logging.error(str(sys.exc_info()))


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

    # instantiate class
    setup = Setup(logging)

    # run functions
    setup.setup_dynamodb()
    setup.create_stacks('config_rules')
    setup.create_stacks('custom_rules')