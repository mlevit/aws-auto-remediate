import boto3
import logging


class SNSLoggingHandler(logging.Handler):
    def __init__(self, topic_arn):
        logging.Handler.__init__(self)
        self.client = boto3.client('sns')
        self.topic_arn = topic_arn

    def emit(self, record):
        self.client.publish(
            TopicArn=self.topic_arn,
            Message=f"[{record.levelname}] {record.getMessage()}")