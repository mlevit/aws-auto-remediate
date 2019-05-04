import boto3
import logging
import os
import sys

class Retry:
    def __init__(self, logging):
        # parameters
        self.logging = logging

    def retry_security_events(self):
        client = boto3.client('sqs')
        queue_url = self.get_queue_url()
        
        try:
            response = client.receive_message(
                QueueUrl=queue_url,
                MaxNumberOfMessages=10)
        except:
            self.logging.error("Could not retrieve Messages from SQS Queue URL '%s'." % queue_url)
            self.logging.error(str(sys.exc_info()))
        
        while 'Messages' in response:
            for message in response.get('Messages'):
                receipt_handle = message.get('ReceiptHandle')
                body = message.get('Body')

                # invoke Auto Remediate Lambda Function
                self.invoke_function(body)

                # delete message from SQS Queue
                try:
                    client.delete_message(
                        QueueUrl=queue_url,
                        ReceiptHandle=receipt_handle)
                except:
                    self.logging.error("Could not delete Message '%s' from "
                                       "SQS Queue URL '%s'." % (receipt_handle, queue_url))
                    self.logging.error(str(sys.exc_info()))
                    continue
            
            # get the next 10 messages
            try:
                response = client.receive_message(
                    QueueUrl=queue_url,
                    MaxNumberOfMessages=10)
            except:
                self.logging.error("Could not retrieve Messages from SQS Queue URL '%s'." % queue_url)
                self.logging.error(str(sys.exc_info()))

    def invoke_function(self, message):
        """
        Invoke Auto Remediate function
        """
        
        client = boto3.client('lambda')
        try:
            client.invoke(
                FunctionName=os.environ.get('LAMBDANAME'),
                InvocationType='Event',
                Payload=bytes(message, 'utf-8'))
        except:
            self.logging.error("Could not invoke Lambda Function '%s' "
                               "with payload '%s'." % (os.environ.get('LAMBDANAME'), message))
            self.logging.error(str(sys.exc_info()))

    def get_queue_url(self):
        """
        Retrieves the SQS Queue URL from the SQS Queue Name
        """

        client = boto3.client('sqs')
        
        try:
            response = client.get_queue_url(QueueName=os.environ.get('DLQNAME'))
            return response.get('QueueUrl')
        except:
            self.logging.error("Could not retrieve SQS Queue URL for SQS Queue '%s'." % os.environ.get('DLQNAME'))
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
    retry = Retry(logging)

    # run functions
    retry.retry_security_events()