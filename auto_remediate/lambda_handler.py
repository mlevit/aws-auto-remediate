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
            "securityhub-cmk-backing-key-rotation-enabled": self.security_hub.cmk_backing_key_rotation_enabled,
            "securityhub-iam-password-policy-ensure-expires": self.security_hub.iam_password_policy,
            "securityhub-iam-password-policy-lowercase-letter-check": self.security_hub.iam_password_policy,
            "securityhub-iam-password-policy-minimum-length-check": self.security_hub.iam_password_policy,
            "securityhub-iam-password-policy-number-check": self.security_hub.iam_password_policy,
            "securityhub-iam-password-policy-prevent-reuse-check": self.security_hub.iam_password_policy,
            "securityhub-iam-password-policy-symbol-check": self.security_hub.iam_password_policy,
            "securityhub-iam-password-policy-uppercase-letter-check": self.security_hub.iam_password_policy,
            "securityhub-iam-user-unused-credentials-check": self.security_hub.iam_user_unused_credentials_check,
            "securityhub-restricted-rdp": self.security_hub.restricted_rdp,
            "securityhub-restricted-ssh": self.security_hub.restricted_ssh,
            "securityhub-s3-bucket-public-read-prohibited": self.security_hub.s3_bucket_public_read_prohibited,
            "securityhub-s3-bucket-public-write-prohibited": self.security_hub.s3_bucket_public_write_prohibited,
            "securityhub-s3-bucket-logging-enabled": self.security_hub.s3_bucket_logging_enabled,
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
                            self.send_to_dlq(
                                config_payload, Remediate.get_try_count(record)
                            )
                    else:
                        self.logging.warning(
                            f"No remediation available for Config Rule "
                            f"'{config_rule_name}' with payload '{config_payload}'."
                        )
                else:
                    self.logging.info(
                        f"Config Rule '{config_rule_name}' was not remediated based on user preferences."
                    )
            else:
                self.logging.info(
                    f"Resource '{config_rule_resource_id}' is compliant for Config Rule '{config_rule_name}'."
                )

    def intend_to_remediate(self, config_rule_name):
        return (
            self.settings.get("rules").get(config_rule_name, {}).get("remediate", True)
        )

    def get_settings(self):
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

    def send_to_dlq(self, config_payload, try_count):
        """
        Sends the AWS Config payload to the DLQ.
        """
        client = boto3.client("sqs")

        try_count = int(try_count) + 1
        if try_count < int(os.environ.get("RETRYCOUNT", 3)):
            try:
                client.send_message(
                    QueueUrl=self.get_queue_url(),
                    MessageBody=json.dumps(config_payload),
                    MessageAttributes={
                        "try_count": {
                            "StringValue": str(try_count),
                            "DataType": "Number",
                        }
                    },
                )

                self.logging.debug(
                    f"Remediation failed. Payload has been sent to DLQ '{os.environ.get('DLQ')}'."
                )
            except:
                self.logging.error(
                    f"Could not send payload to DLQ '{os.environ.get('DLQ')}'."
                )
                self.logging.error(sys.exc_info()[1])
        else:
            self.logging.warning(
                f"Could not remediate Config change within an "
                f"acceptable number of retries for payload '{config_payload}'."
            )

    def get_queue_url(self):
        """
        Retrieves the SQS Queue URL from the SQS Queue Name.
        """
        client = boto3.client("sqs")

        try:
            response = client.get_queue_url(QueueName=os.environ.get("DLQ"))
            return response.get("QueueUrl")
        except:
            self.logging.error(
                f"Could not retrieve SQS Queue URL for SQS Queue '{os.environ.get('DLQ')}'."
            )
            self.logging.error(sys.exc_info()[1])

    @staticmethod
    def get_config_rule_name(config_payload):
        config_rule_name = config_payload.get("detail").get("configRuleName")
        if "securityhub" in config_rule_name:
            # remove random alphanumeric string suffixed to each
            # Security Hub rule
            return config_rule_name[: config_rule_name.rfind("-")]
        else:
            return config_rule_name

    @staticmethod
    def get_config_rule_compliance(config_payload):
        return (
            config_payload.get("detail")
            .get("newEvaluationResult")
            .get("complianceType")
        )

    @staticmethod
    def get_config_rule_resource_id(config_payload):
        return config_payload.get("detail").get("resourceId")

    @staticmethod
    def get_try_count(record):
        return (
            record.get("messageAttributes", {})
            .get("try_count", {})
            .get("stringValue", "0")
        )


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
