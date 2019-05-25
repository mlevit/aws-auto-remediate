import datetime
import json
import logging
import os
import py

import moto
import pytest

from .. import lambda_handler


class TestDeleteFromQueue:
    @pytest.fixture
    def retry(self):
        with moto.mock_sqs():
            retry = lambda_handler.Retry(logging)
            yield retry

    def test_invalid_queue_url(self, retry):
        """Tests sending message to queue with invalid queue URL
        
        Arguments:
            retry {class} -- Instance of Retry class
        """
        assert not retry.delete_from_queue("http://invalid_queue_url.com", "12345")

    def test_delete_from_queue(self, retry):
        """Tests deletion of a message from a queue
        
        Arguments:
            retry {class} -- Instance of Retry class
        """
        # create queue
        retry.client_sqs.create_queue(QueueName="DEADLETTERQUEUE")

        # get queue url
        response = retry.client_sqs.get_queue_url(QueueName="DEADLETTERQUEUE")
        queue_url = response["QueueUrl"]

        # send message to queue
        retry.client_sqs.send_message(QueueUrl=queue_url, MessageBody="payload")

        # test message in queue
        response = retry.client_sqs.receive_message(QueueUrl=queue_url)
        assert len(response["Messages"]) == 1

        # test delete_from_queue function
        retry.delete_from_queue(queue_url, response["Messages"][0]["ReceiptHandle"])

        response = retry.client_sqs.receive_message(QueueUrl=queue_url)

        # test no messages in queue
        assert "Messages" not in response


class TestRetrySecurityEvents:
    @pytest.fixture
    def retry(self):
        with moto.mock_sqs():
            retry = lambda_handler.Retry(logging)
            yield retry

    @pytest.fixture
    def test_config_payload(self):
        config_payload_file = "auto_remediate_dlq/test/data/config_payload.json"
        with open(config_payload_file, "r") as file:
            config_payload = file.read()

        yield json.loads(config_payload)

    def test_invalid_queue_url(self, retry):
        """Tests sending message to queue with invalid queue URL
        
        Arguments:
            retry {class} -- Instance of Retry class
        """
        # create queue
        retry.client_sqs.create_queue(QueueName="DEADLETTERQUEUE")
        os.environ["DEADLETTERQUEUE"] = "http://invalid_queue_url.com"

        # test retry_security_events function
        assert not retry.retry_security_events()

    def test_retry_security_events(self, retry, test_config_payload):
        """Tests a "retry" of a security event. The test will retrieve a message from the DEADLETTERQUEUE
        and send that message to the COMPLIANCEQUEUE afterwich it'll delete the message
        from the DEADLETTERQUEUE
        
        Arguments:
            retry {class} -- Instance of Retry class
            test_config_payload {dictionary} -- Mock AWS Config payload
        """
        # create queues
        retry.client_sqs.create_queue(QueueName="COMPLIANCEQUEUE")
        retry.client_sqs.create_queue(QueueName="DEADLETTERQUEUE")

        # get COMPLIANCEQUEUE url
        response = retry.client_sqs.get_queue_url(QueueName="COMPLIANCEQUEUE")
        compliance_queue_url = response["QueueUrl"]
        os.environ["COMPLIANCEQUEUE"] = compliance_queue_url

        # get DEADLETTERQUEUE url
        response = retry.client_sqs.get_queue_url(QueueName="DEADLETTERQUEUE")
        dlq_queue_url = response["QueueUrl"]
        os.environ["DEADLETTERQUEUE"] = dlq_queue_url

        retry.client_sqs.send_message(
            QueueUrl=dlq_queue_url,
            MessageBody=json.dumps(test_config_payload),
            MessageAttributes={"try_count": {"StringValue": "1", "DataType": "Number"}},
        )

        # test retry_security_events function
        retry.retry_security_events()

        # assert 0 messages in queue
        response = retry.client_sqs.receive_message(QueueUrl=dlq_queue_url)
        assert "Messages" not in response

        # assert 1 message in queue
        response = retry.client_sqs.receive_message(QueueUrl=compliance_queue_url)
        assert len(response["Messages"]) == 1


class TestSendToComplianceQueue:
    @pytest.fixture
    def retry(self):
        with moto.mock_sqs():
            retry = lambda_handler.Retry(logging)
            yield retry

    def test_invalid_queue_url(self, retry):
        """Tests sending message to queue with invalid queue URL
        
        Arguments:
            retry {class} -- Instance of Retry class
        """
        # create queue
        retry.client_sqs.create_queue(QueueName="COMPLIANCEQUEUE")
        os.environ["COMPLIANCEQUEUE"] = "http://invalid_queue_url.com"

        # test send_to_compliance_queue function
        assert not retry.send_to_compliance_queue("payload", "1")

    def test_send_to_compliance_queue(self, retry):
        """Tests sending message to queue
        
        Arguments:
            retry {class} -- Instance of Retry class
        """
        # create queue
        retry.client_sqs.create_queue(QueueName="COMPLIANCEQUEUE")

        # get queue url
        response = retry.client_sqs.get_queue_url(QueueName="COMPLIANCEQUEUE")
        queue_url = response["QueueUrl"]

        # set environment variable
        os.environ["COMPLIANCEQUEUE"] = queue_url

        # test send_to_compliance_queue function
        retry.send_to_compliance_queue("payload", "1")
        response = retry.client_sqs.receive_message(
            QueueUrl=os.environ["COMPLIANCEQUEUE"]
        )

        # assert 1 message in queue
        assert len(response["Messages"]) == 1

        # assert payload
        assert response["Messages"][0]["Body"] == "payload"

        # assert try_count
        assert (
            response["Messages"][0]["MessageAttributes"]["try_count"]["StringValue"]
            == "1"
        )


class TestStaticMethods:
    @pytest.fixture
    def retry(self):
        retry = lambda_handler.Retry(logging)
        yield retry

    @pytest.fixture
    def test_config_payload(self):
        config_payload_file = "auto_remediate_dlq/test/data/config_payload.json"
        with open(config_payload_file, "r") as file:
            config_payload = file.read()

        yield json.loads(config_payload)

    def test_get_config_rule_compliance(self, retry, test_config_payload):
        """Tests retrieval of Config Rule compliance
        
        Arguments:
            retry {class} -- Instance of Retry class
            test_config_payload {dictionary} -- AWS Config Payload
        """
        # validate test
        assert retry.get_config_rule_compliance(test_config_payload) == "NON_COMPLIANT"

    def test_get_config_rule_name(self, retry, test_config_payload):
        """Tests retrieval of Config Rule name
        
        Arguments:
            retry {class} -- Instance of Retry class
            test_config_payload {dictionary} -- AWS Config Payload
        """
        # validate test
        assert (
            retry.get_config_rule_name(test_config_payload)
            == "securityhub-vpc-flow-logs-enabled-l6dseq"
        )
