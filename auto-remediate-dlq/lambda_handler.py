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
            self.logging.error(sys.exc_info())
        
        while 'Messages' in response:
            for message in response.get('Messages'):
                receipt_handle = message.get('ReceiptHandle')
                body = message.get('Body')
                
                # invoke Auto Remediate Lambda Function
                invoke_function = self.invoke_function(body)
                
                # delete message from SQS Queue if function
                # was invoked successfully
                if invoke_function:
                    self.delete_message(queue_url, receipt_handle)
                else:
                    self.logging.debug("Did not delete Message '%s' from "
                                       "SQS Queue URL '%s'. due to Lambda Function "
                                       "invocation error." % (receipt_handle, queue_url))
            
            # get the next 10 messages
            try:
                response = client.receive_message(
                    QueueUrl=queue_url,
                    MaxNumberOfMessages=10)
            except:
                self.logging.error("Could not retrieve Messages from SQS Queue URL '%s'." % queue_url)
                self.logging.error(sys.exc_info())

    def invoke_function(self, message):
        """
        Invoke Auto Remediate function. Return True if 
        invocation was was successfull
        """
        client = boto3.client('lambda')
        try:
            client.invoke(
                FunctionName=os.environ.get('LAMBDANAME'),
                InvocationType='Event',
                Payload=bytes(message, 'utf-8'))

            self.logging.info("Invoked Lambda Function '%s' for "
                              "security event reprocessing." % os.environ.get('LAMBDANAME'))
            
            return True
        except:
            self.logging.error("Could not invoke Lambda Function '%s' "
                               "with payload '%s'." % (os.environ.get('LAMBDANAME'), message))
            self.logging.error(sys.exc_info())
            
            return False
    
    def delete_message(self, queue_url, receipt_handle):
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
            self.logging.error(sys.exc_info())

    def get_queue_url(self):
        """
        Retrieves the SQS Queue URL from the SQS Queue Name
        """
        client = boto3.client('sqs')
        
        try:
            response = client.get_queue_url(QueueName=os.environ.get('DLQNAME'))
            return response.get('QueueUrl')
        except:
            self.logging.error("Could not retrieve SQS Queue URL "
                               "for SQS Queue '%s'." % os.environ.get('DLQNAME'))
            self.logging.error(sys.exc_info())


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