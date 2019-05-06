import ast
import boto3
import json
import logging
import os
import sys

class Retry:
    def __init__(self, logging):
        # parameters
        self.logging = logging

    def retry_security_events(self):
        client = boto3.client('sqs')
        queue_url = self.get_queue_url(os.environ.get('DLQ'))
        
        try:
            response = client.receive_message(
                QueueUrl=queue_url,
                MaxNumberOfMessages=10)
        except:
            self.logging.error("Could not retrieve Messages from SQS Queue URL '%s'." % queue_url)
            self.logging.error(sys.exc_info()[1])
        
        while 'Messages' in response:
            for message in response.get('Messages'):
                receipt_handle = message.get('ReceiptHandle')
                body = ast.literal_eval(message.get('Body'))
                
                for record in body.get('Records'):
                    if self.send_to_queue(record.get('body')):
                        self.delete_from_queue(queue_url, receipt_handle)
            
            # get the next 10 messages
            try:
                response = client.receive_message(
                    QueueUrl=queue_url,
                    MaxNumberOfMessages=10)
            except:
                self.logging.error("Could not retrieve Messages from SQS Queue URL '%s'." % queue_url)
                self.logging.error(sys.exc_info()[1])
    
    @staticmethod
    def get_config_rule_name(record):
        return record.get('detail').get('configRuleName')
    
    @staticmethod
    def get_config_rule_compliance(record):
        return record.get('detail').get('newEvaluationResult').get('complianceType')
    
    def send_to_queue(self, message):
        """
        Sends a message to an SQS Queue.
        """
        client = boto3.client('sqs')
        queue_url = self.get_queue_url(os.environ.get('COMPLIANCEQUEUE'))
        
        try:
            client.send_message(
                QueueUrl=queue_url,
                MessageBody=message)
            
            self.logging.debug("Message payload sent to SQS Queue '%s'." % os.environ.get('COMPLIANCEQUEUE'))
            return True
        except:
            self.logging.error("Could not send payload to SQS Queue '%s'." % os.environ.get('COMPLIANCEQUEUE'))
            self.logging.error(sys.exc_info()[1])
            return False
    
    def delete_from_queue(self, queue_url, receipt_handle):
        """
        Delete Message from SQS Queue
        """
        client = boto3.client('sqs')
        try:
            client.delete_message(
                QueueUrl=queue_url,
                ReceiptHandle=receipt_handle)
            
            self.logging.info("Deleted Message '%s' from "
                              "SQS Queue URL '%s'." % (receipt_handle, queue_url))
        except:
            self.logging.error("Could not delete Message '%s' from "
                               "SQS Queue URL '%s'." % (receipt_handle, queue_url))
            self.logging.error(sys.exc_info()[1])

    def get_queue_url(self, queue_name):
        """
        Retrieves the SQS Queue URL from the SQS Queue Name
        """
        client = boto3.client('sqs')
        
        try:
            response = client.get_queue_url(QueueName=queue_name)
            return response.get('QueueUrl')
        except:
            self.logging.error("Could not retrieve SQS Queue URL "
                               "for SQS Queue '%s'." % queue_name)
            self.logging.error(sys.exc_info()[1])


def lambda_handler(event, context):
    logger = logging.getLogger()

    if logger.handlers:
        for handler in logger.handlers:
            logger.removeHandler(handler)
    
    # change logging levels for boto and others
    logging.getLogger('boto3').setLevel(logging.ERROR)
    logging.getLogger('botocore').setLevel(logging.ERROR)
    logging.getLogger('urllib3').setLevel(logging.ERROR)
    
    # set logging format
    logging.basicConfig(format="[%(levelname)s] %(message)s (%(filename)s, %(funcName)s(), line %(lineno)d)",
                        level=os.environ.get('LOGLEVEL', 'WARNING').upper())

    # instantiate class
    retry = Retry(logging)

    # run functions
    retry.retry_security_events()