import logging
import os
import sys

import boto3


class Retry:
    def __init__(self, logging):
        # parameters
        self.logging = logging

        self._client_sts = None
        self._client_sqs = None

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
    def client_sqs(self):
        if not self._client_sqs:
            self._client_sqs = boto3.client("sqs", self.region)
        return self._client_sqs

    def retry_security_events(self):
        """Retrieves messages from the DLQ and sends them back into the 
        compliance SQS Queue for reprocessing.
        """
        queue_url = os.environ.get("DEADLETTERQUEUE")
        response = self.receive_message(queue_url)

        while "Messages" in response:
            for message in response.get("Messages"):
                receipt_handle = message.get("ReceiptHandle")
                body = message.get("Body")
                try_count = (
                    message.get("MessageAttributes", {})
                    .get("try_count", {})
                    .get("StringValue", "1")
                )

                if self.send_to_compliance_queue(body, try_count):
                    self.delete_from_queue(queue_url, receipt_handle)

                response = self.receive_message(queue_url)

    def delete_from_queue(self, queue_url, receipt_handle):
        """Delete a Message from an SQS Queue.
        
        Arguments:
            queue_url {string} -- URL of an SQS Queue
            receipt_handle {string} -- The receipt handle associated with the message to delete
        """
        try:
            self.client_sqs.delete_message(
                QueueUrl=queue_url, ReceiptHandle=receipt_handle
            )

            self.logging.info(
                f"Deleted Message '{receipt_handle}' from SQS Queue URL '{queue_url}'."
            )
            return True
        except:
            self.logging.error(
                f"Could not delete Message '{receipt_handle}' from SQS Queue URL '{queue_url}'."
            )
            self.logging.error(sys.exc_info()[1])
            return False

    def receive_message(self, queue_url):
        """Retrieves 10 messeges from an SQS Queue
        
        Arguments:
            queue_url {string} -- SQS Queue URL
        
        Returns:
            dictionary -- Dictionary of SQS messeges
        """
        try:
            return self.client_sqs.receive_message(
                QueueUrl=queue_url,
                MessageAttributeNames=["try_count"],
                MaxNumberOfMessages=10,
            )
        except:
            self.logging.error(
                f"Could not retrieve Messages from SQS Queue URL '{queue_url}'."
            )
            self.logging.error(sys.exc_info()[1])
            return {}

    def send_to_compliance_queue(self, config_payload, try_count):
        """Sends a message to the Config Compliance SQS Queue.
        
        Arguments:
            config_payload {string} -- AWS Config payload
            try_count {string} -- Number of attempted remediations for a given AWS Config Rule
        
        Returns:
            boolean -- True if sending message to SQS was successful
        """
        queue_url = os.environ.get("COMPLIANCEQUEUE")

        try:
            self.client_sqs.send_message(
                QueueUrl=queue_url,
                MessageBody=config_payload,
                MessageAttributes={
                    "try_count": {"StringValue": try_count, "DataType": "Number"}
                },
            )

            self.logging.debug(f"Message payload sent to SQS Queue '{queue_url}'.")
            return True
        except:
            self.logging.error(f"Could not send payload to SQS Queue '{queue_url}'.")
            self.logging.error(sys.exc_info()[1])
            return False

    @staticmethod
    def get_config_rule_compliance(record):
        """Retrieves the AWS Config rule compliance variable
        
        Arguments:
            config_payload {JSON} -- AWS Config payload
        
        Returns:
            string -- COMPLIANT | NON_COMPLIANT
        """
        return record.get("detail").get("newEvaluationResult").get("complianceType")

    @staticmethod
    def get_config_rule_name(record):
        """Retrieves the AWS Config rule name variable. For Security Hub rules, the random
        suffixed alphanumeric characters will be removed.
        
        Arguments:
            config_payload {JSON} -- AWS Config payload
        
        Returns:
            string -- AWS Config rule name
        """
        return record.get("detail").get("configRuleName")


def lambda_handler(event, context):
    logger = logging.getLogger()

    if logger.handlers:
        for handler in logger.handlers:
            logger.removeHandler(handler)

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
    retry = Retry(logging)

    # run functions
    retry.retry_security_events()
