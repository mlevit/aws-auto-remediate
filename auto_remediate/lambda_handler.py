import json
import logging
import os
import sys

import boto3
from dynamodb_json import json_util as dynamodb_json

from config_rules import *
from custom_rules import *
from security_hub_rules import *
from sns_logging_handler import *


class Remediate:
    def __init__(self, logging, event):
        # parameters
        self.logging = logging
        self.event = event

        # event payload
        self.logging.debug(f"Event payload: {self.event}")

        # variables
        self.settings = self.get_settings()

        # classes
        self.config = ConfigRules(self.logging)
        self.security_hub = SecurityHubRules(self.logging)
        self.custom = CustomRules(self.logging)

        # remediation function dict
        self.remediation_functions = {
            # config
            "auto-remediate-rds-instance-public-access-check": self.config.rds_instance_public_access_check,
            # security hub
            "securityhub-access-keys-rotated": self.security_hub.access_keys_rotated,
            "securityhub-cloud-trail-cloud-watch-logs-enabled": self.security_hub.cloud_trail_cloud_watch_logs_enabled,
            "securityhub-cloud-trail-encryption-enabled": self.security_hub.cloud_trail_encryption_enabled,
            "securityhub-cmk-backing-key-rotation-enabled": self.security_hub.cmk_backing_key_rotation_enabled,
            "securityhub-iam-password-policy-ensure-expires": self.security_hub.iam_password_policy,
            "securityhub-iam-password-policy-lowercase-letter-check": self.security_hub.iam_password_policy,
            "securityhub-iam-password-policy-minimum-length-check": self.security_hub.iam_password_policy,
            "securityhub-iam-password-policy-number-check": self.security_hub.iam_password_policy,
            "securityhub-iam-password-policy-prevent-reuse-check": self.security_hub.iam_password_policy,
            "securityhub-iam-password-policy-symbol-check": self.security_hub.iam_password_policy,
            "securityhub-iam-password-policy-uppercase-letter-check": self.security_hub.iam_password_policy,
            "securityhub-iam-policy-no-statements-with-admin-access": self.security_hub.iam_policy_no_statements_with_admin_access,
            "securityhub-iam-user-no-policies-check": self.security_hub.iam_user_no_policies_check,
            "securityhub-iam-user-unused-credentials-check": self.security_hub.iam_user_unused_credentials_check,
            "securityhub-restricted-rdp": self.security_hub.restricted_rdp,
            "securityhub-restricted-ssh": self.security_hub.restricted_ssh,
            "securityhub-s3-bucket-logging-enabled": self.security_hub.s3_bucket_logging_enabled,
            "securityhub-s3-bucket-public-read-prohibited": self.security_hub.s3_bucket_public_read_prohibited,
            "securityhub-s3-bucket-public-write-prohibited": self.security_hub.s3_bucket_public_write_prohibited,
            "securityhub-vpc-default-security-group-closed": self.security_hub.vpc_default_security_group_closed,
            "securityhub-vpc-flow-logs-enabled": self.security_hub.vpc_flow_logs_enabled
            # custom
        }

    def remediate(self):
        for record in self.event.get("Records"):
            config_payload = json.loads(record.get("body"))
            config_rule_name = Remediate.get_config_rule_name(config_payload)
            config_rule_compliance = Remediate.get_config_rule_compliance(
                config_payload
            )
            config_rule_resource_id = Remediate.get_config_rule_resource_id(
                config_payload
            )

            if config_rule_compliance == "NON_COMPLIANT":
                if self.intend_to_remediate(config_rule_name):
                    remediation_function = self.remediation_functions.get(
                        config_rule_name, None
                    )

                    if remediation_function is not None:
                        if not remediation_function(config_rule_resource_id):
                            self.send_to_dead_letter_queue(
                                config_payload, Remediate.get_try_count(record)
                            )
                    else:
                        self.logging.warning(
                            f"No remediation available for Config Rule "
                            f"'{config_rule_name}' with payload '{config_payload}'."
                        )
                        self.send_to_missing_remediation_topic(
                            config_rule_name, config_payload
                        )
                else:
                    self.logging.info(
                        f"Config Rule '{config_rule_name}' was not remediated based on user preferences."
                    )
            else:
                self.logging.info(
                    f"Resource '{config_rule_resource_id}' is compliant for Config Rule '{config_rule_name}'."
                )

    @staticmethod
    def get_config_rule_compliance(config_payload):
        """Retrieves the AWS Config rule compliance variable
        
        Arguments:
            config_payload {dictionary} -- AWS Config payload
        
        Returns:
            string -- COMPLIANT | NON_COMPLIANT
        """
        return (
            config_payload.get("detail")
            .get("newEvaluationResult")
            .get("complianceType")
        )

    @staticmethod
    def get_config_rule_name(config_payload):
        """Retrieves the AWS Config rule name variable. For Security Hub rules, the random
        suffixed alphanumeric characters will be removed.
        
        Arguments:
            config_payload {dictionary} -- AWS Config payload
        
        Returns:
            string -- AWS Config rule name
        """
        config_rule_name = config_payload.get("detail").get("configRuleName")
        if "securityhub" in config_rule_name:
            # remove random alphanumeric string suffixed to each
            # Security Hub rule
            return config_rule_name[: config_rule_name.rfind("-")]
        else:
            return config_rule_name

    @staticmethod
    def get_config_rule_resource_id(config_payload):
        """Retrieves the AWS Config Resource ID from the AWS Config payload
        
        Arguments:
            config_payload {dictionary} -- AWS Config payload
        
        Returns:
            string -- Resource ID relating to the AWS Resource that triggered the AWS Config Rule
        """
        return config_payload.get("detail").get("resourceId")

    def get_settings(self):
        """Return the DynamoDB aws-auto-remediate-settings table in a Python dict format
        
        Returns:
            dict -- aws-auto-remediate-settings table
        """
        settings = {}
        try:
            for record in boto3.client("dynamodb").scan(
                TableName=os.environ["SETTINGSTABLE"]
            )["Items"]:
                record_json = dynamodb_json.loads(record, True)
                settings[record_json.get("key")] = record_json.get("value")
        except:
            self.logging.error(
                f"Could not read DynamoDB table '{os.environ['SETTINGSTABLE']}'."
            )
            self.logging.error(sys.exc_info()[1])

        return settings

    @staticmethod
    def get_try_count(record):
        """Retrieves the "try_count" key from the SQS Record payload from a custom
        SQS Message Attribute
        
        Arguments:
            record {dictionary} -- SQS Record payload
        
        Returns:
            string -- Number of attempted remediations for a given AWS Config Rule
        """
        return (
            record.get("messageAttributes", {})
            .get("try_count", {})
            .get("stringValue", "0")
        )

    def intend_to_remediate(self, config_rule_name):
        """Returns whether an AWS Config Rule should be remediated based on user preferences.
        
        Arguments:
            config_rule_name {string} -- AWS Config Rule name
        
        Returns:
            boolean -- True | False
        """
        return (
            self.settings.get("rules", {})
            .get(config_rule_name, {})
            .get("remediate", True)
        )

    def send_to_dead_letter_queue(self, config_payload, try_count):
        """Sends the AWS Config payload to an SQS Queue (DLQ) if after incrementing 
        the "try_count" variable it is below the user defined "RETRYCOUNT" setting.
        
        Arguments:
            config_payload {dictionary} -- AWS Config payload
            try_count {string} -- Number of previos remediation attemps for this AWS Config payload
        """
        client = boto3.client("sqs")

        try_count = int(try_count) + 1
        if try_count < int(os.environ.get("RETRYCOUNT", 3)):
            try:
                client.send_message(
                    QueueUrl=os.environ.get("DEADLETTERQUEUE"),
                    MessageBody=json.dumps(config_payload),
                    MessageAttributes={
                        "try_count": {
                            "StringValue": str(try_count),
                            "DataType": "Number",
                        }
                    },
                )

                self.logging.debug(
                    f"Remediation failed. Payload has been sent to SQS DLQ '{os.environ.get('DEADLETTERQUEUE')}'."
                )
            except:
                self.logging.error(
                    f"Could not send payload to SQS DLQ '{os.environ.get('DEADLETTERQUEUE')}'."
                )
                self.logging.error(sys.exc_info()[1])
        else:
            self.logging.warning(
                f"Could not remediate Config change within an "
                f"acceptable number of retries for payload '{config_payload}'."
            )

    def send_to_missing_remediation_topic(self, config_rule_name, config_payload):
        """Publishes a message onto the missing remediation SNS Topic. The topic should be subscribed to
        by administrators to be aware when their security remediations are not fully covered.
        
        Arguments:
            config_rule_name {string} -- AWS Config Rule name
            config_payload {dictionary} -- AWS Config Rule payload
        """
        client = boto3.client("sns")
        topic_arn = os.environ.get("MISSINGREMEDIATIONTOPIC")

        try:
            client.publish(
                TopicArn=topic_arn,
                Message=json.dumps(config_payload),
                Subject=f"No remediation available for Config Rule '{config_rule_name}'",
            )
        except:
            self.logging.error(f"Could not publish to SNS Topic 'topic_arn'.")


def lambda_handler(event, context):
    loggger = logging.getLogger()

    if loggger.handlers:
        for handler in loggger.handlers:
            loggger.removeHandler(handler)

    # change logging levels for boto and others to prevent log spamming
    logging.getLogger("boto3").setLevel(logging.ERROR)
    logging.getLogger("botocore").setLevel(logging.ERROR)
    logging.getLogger("urllib3").setLevel(logging.ERROR)

    # set logging format
    logging.basicConfig(
        format="[%(levelname)s] %(message)s (%(filename)s, %(funcName)s(), line %(lineno)d)",
        level=os.environ.get("LOGLEVEL", "WARNING"),
    )

    # add SNS logger
    # sns_logger = SNSLoggingHandler(os.environ.get('LOGTOPIC'))
    # sns_logger.setLevel(logging.INFO)
    # loggger.addHandler(sns_logger)

    # instantiate class
    remediate = Remediate(logging, event)

    # run functions
    remediate.remediate()
