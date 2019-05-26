import fnmatch
import json
import logging
import os
import sys

import boto3
from dynamodb_json import json_util as dynamodb_json


class Setup:
    def __init__(self, logging):
        # parameters
        self.logging = logging

        self._client_cloudformation = None
        self._client_dynamodb = None
        self._client_sts = None

    @property
    def client_sts(self):
        if not self._client_sts:
            self._client_sts = boto3.client("sts")
        return self._client_sts

    @property
    def region(self):
        if self.client_sts.meta.region_name != "aws-global":
            return self.client_sts.meta.region_name
        else:
            return "us-east-1"

    @property
    def client_cloudformation(self):
        if not self._client_cloudformation:
            self._client_cloudformation = boto3.client("cloudformation", self.region)
        return self._client_cloudformation

    @property
    def client_dynamodb(self):
        if not self._client_dynamodb:
            self._client_dynamodb = boto3.client("dynamodb", self.region)
        return self._client_dynamodb

    def create_stacks(self, stack_sub_dir, settings):
        """Parse a directory and and deploy all the AWS Config Rules it contains
        
        Arguments:
            stack_sub_dir {string} -- Sub-directory that houses AWS Config Rules
            settings {dictionary} -- Dictionary of settings
        """
        existing_stacks = self.get_current_stacks()
        path = f"auto_remediate_setup/data/{stack_sub_dir}"

        for file in os.listdir(path):
            if fnmatch.fnmatch(file, "*.json"):
                stack_name = file.replace(".json", "")
                template_body = None

                with open(os.path.join(path, file)) as stack:
                    template_body = str(stack.read())

                if stack_name not in existing_stacks:
                    if (
                        settings.get("rules", {})
                        .get(stack_name, {})
                        .get("deploy", True)
                    ):
                        try:
                            self.client_cloudformation.create_stack(
                                StackName=stack_name,
                                TemplateBody=template_body,
                                OnFailure="DELETE",
                                EnableTerminationProtection=True,
                            )

                            self.logging.info(
                                f"Creating AWS Config Rule '{stack_name}'."
                            )
                        except:
                            self.logging.error(
                                f"Could not create AWS Config Rule '{stack_name}'."
                            )
                            self.logging.error(sys.exc_info()[1])
                            continue
                    else:
                        self.logging.info(
                            f"AWS Config Rule '{stack_name}' deployement was skipped due to user preferences."
                        )
                else:
                    if (
                        not settings.get("rules", {})
                        .get(stack_name, {})
                        .get("deploy", True)
                    ):
                        self.client_cloudformation.update_termination_protection(
                            EnableTerminationProtection=False, StackName=stack_name
                        )
                        self.client_cloudformation.delete_stack(StackName=stack_name)
                        self.logging.info(
                            f"AWS Config Rule '{stack_name}' was deleted."
                        )
                    else:
                        self.logging.debug(
                            f"AWS Config Rule '{stack_name}' already exists."
                        )

    def get_current_stacks(self):
        """Retrieve a list of all CloudFormation Stacks currently deployed your AWS accont and region
        
        Returns:
            list -- List of currently deployed AWS Config Rules
        """
        try:
            resources = self.client_cloudformation.list_stacks().get("StackSummaries")
        except:
            self.logging.error(sys.exc_info()[1])
            return None

        existing_stacks = []
        for resource in resources:
            if resource.get("StackStatus") not in ("DELETE_COMPLETE"):
                existing_stacks.append(resource.get("StackName"))

        return existing_stacks

    def get_settings(self):
        """Return the DynamoDB aws-auto-remediate-settings table in a Python dict format
        
        Returns:
            dict -- aws-auto-remediate-settings table
        """
        settings = {}
        try:
            for record in self.client_dynamodb.scan(
                TableName=os.environ["SETTINGSTABLE"]
            )["Items"]:
                record_json = dynamodb_json.loads(record, True)

                if "key" in record_json and "value" in record_json:
                    settings[record_json.get("key")] = record_json.get("value")
        except:
            self.logging.error(
                f"Could not read DynamoDB table '{os.environ['SETTINGSTABLE']}'."
            )
            self.logging.error(sys.exc_info()[1])

        return settings

    def setup_dynamodb(self):
        """Inserts all the default settings into a DynamoDB table.
        """
        try:
            settings_data = open(
                "auto_remediate_setup/data/auto-remediate-settings.json"
            )
            settings_json = json.loads(settings_data.read())

            update_settings = False

            # get current settings version
            current_version = self.client_dynamodb.get_item(
                TableName=os.environ["SETTINGSTABLE"],
                Key={"key": {"S": "version"}},
                ConsistentRead=True,
            )

            # get new settings version
            new_version = float(settings_json[0].get("value", {}).get("N", 0.0))

            # check if settings exist and if they're older than current settings
            if "Item" in current_version:
                current_version = float(
                    current_version.get("Item").get("value").get("N")
                )
                if current_version < new_version:
                    update_settings = True
                    self.logging.info(
                        f"Existing settings with version {str(current_version)} are being updated to version "
                        f"{str(new_version)} in DynamoDB Table '{os.environ['SETTINGSTABLE']}'."
                    )
                else:
                    self.logging.debug(
                        f"Existing settings are at the lastest version {str(current_version)} in DynamoDB Table "
                        f"'{os.environ['SETTINGSTABLE']}'."
                    )
            else:
                update_settings = True
                self.logging.info(
                    f"Settings are being inserted into DynamoDB Table "
                    f"'{os.environ['SETTINGSTABLE']}' for the first time."
                )

            if update_settings:
                for setting in settings_json:
                    try:
                        self.client_dynamodb.put_item(
                            TableName=os.environ["SETTINGSTABLE"], Item=setting
                        )
                    except:
                        self.logging.error(sys.exc_info()[1])
                        continue

            settings_data.close()
        except:
            self.logging.error(sys.exc_info()[1])


def lambda_handler(event, context):
    loggger = logging.getLogger()

    if loggger.handlers:
        for handler in loggger.handlers:
            loggger.removeHandler(handler)

    # change logging levels for boto and others
    logging.getLogger("boto3").setLevel(logging.ERROR)
    logging.getLogger("botocore").setLevel(logging.ERROR)
    logging.getLogger("urllib3").setLevel(logging.ERROR)

    # set logging format
    logging.basicConfig(
        format="[%(levelname)s] %(message)s (%(filename)s, %(funcName)s(), line %(lineno)d)",
        level=os.environ.get("LOGLEVEL", "WARNING").upper(),
    )

    # instantiate class
    setup = Setup(logging)

    # run functions
    setup.setup_dynamodb()

    settings = setup.get_settings()

    setup.create_stacks("config_rules", settings)
    setup.create_stacks("custom_rules", settings)
