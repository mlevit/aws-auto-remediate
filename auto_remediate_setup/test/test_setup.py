import datetime
import json
import logging
import os
import py

import moto
import pytest

from .. import lambda_handler


class TestCreateStacks:
    @pytest.fixture
    def setup(self):
        with moto.mock_cloudformation():
            setup = lambda_handler.Setup(logging)
            yield setup

    def test_create_stacks(self, setup):
        setup.create_stacks("config_rules", {})


class TestGetSettings:
    @pytest.fixture
    def setup(self):
        with moto.mock_cloudformation(), moto.mock_dynamodb2(), moto.mock_sts():
            setup = lambda_handler.Setup(logging)
            yield setup

    def test_get_settings(self, setup):
        """Tests retrieval of settings from DynamoDB
        
        Arguments:
            setup {class} -- Instance of Setup class
        """
        os.environ["SETTINGSTABLE"] = "settings_table"

        # create table
        setup.client_dynamodb.create_table(
            TableName="settings_table",
            KeySchema=[{"AttributeName": "key", "KeyType": "HASH"}],
            AttributeDefinitions=[{"AttributeName": "key", "AttributeType": "S"}],
            ProvisionedThroughput={"ReadCapacityUnits": 1, "WriteCapacityUnits": 1},
        )

        # populate table
        setup.client_dynamodb.put_item(
            TableName="settings_table",
            Item={"key": {"S": "version"}, "value": {"N": "1.0"}},
        )

        # test get_settings function
        settings = setup.get_settings()

        # validate test
        assert settings["version"] == 1.0

    def test_invalid_table_schema(self, setup):
        """Tests retrieval of settings from DynamoDB with the wrong schema
        
        Arguments:
            setup {class} -- Instance of Setup class
        """
        os.environ["SETTINGSTABLE"] = "settings_table"

        setup.client_dynamodb.create_table(
            TableName="settings_table",
            KeySchema=[{"AttributeName": "id", "KeyType": "HASH"}],
            AttributeDefinitions=[{"AttributeName": "id", "AttributeType": "S"}],
            ProvisionedThroughput={"ReadCapacityUnits": 1, "WriteCapacityUnits": 1},
        )

        setup.client_dynamodb.put_item(
            TableName="settings_table", Item={"id": {"S": "123"}}
        )

        # test get_settings function
        assert setup.get_settings() == {}

    def test_no_table_name(self, setup):
        """Tests retrieval of settings from DynamoDB with no table name
        
        Arguments:
            setup {class} -- Instance of Setup class
        """
        assert setup.get_settings() == {}


class TestGetCurrentStacks:
    @pytest.fixture
    def setup(self):
        with moto.mock_cloudformation(), moto.mock_dynamodb2(), moto.mock_sts():
            setup = lambda_handler.Setup(logging)
            yield setup

    def test_get_current_stacks(self, setup):
        """Tests retrieval of CloudFormation Stacks
        
        Arguments:
            setup {[type]} -- [description]
        """
        setup.client_cloudformation.create_stack(
            StackName="sample_sqs",
            TemplateBody='{"Resources":{"SQSQueue":{"Type":"AWS::SQS::Queue","Properties":{"QueueName":"test_queue"}}}}',
        )

        # test get_current_stacks function
        response = setup.get_current_stacks()

        # assert stack created
        assert response[0] == "sample_sqs"

    def test_no_stacks(self, setup):
        """Tests retrieval of CloudFormation Stacks with no Stacks
        
        Arguments:
            setup {[type]} -- [description]
        """
        assert setup.get_current_stacks() == []
