import datetime
import json
import logging
import os
import shutil

import moto
import py
import pytest

from .. import lambda_handler


class TestCreateStacks:
    @pytest.fixture
    def setup(self):
        with moto.mock_cloudformation(), moto.mock_dynamodb2(), moto.mock_sts():
            setup = lambda_handler.Setup(logging)
            yield setup

    def test_create_stacks_deployment(self, setup):
        # make mock_rules directory
        os.mkdir("auto_remediate_setup/data/mock_rules")

        # move mock CloudFormation Stacks
        shutil.copyfile(
            "auto_remediate_setup/test/data/mock_rules/cloudtrail-enabled.json",
            "auto_remediate_setup/data/mock_rules/cloudtrail-enabled.json",
        )

        # backup settings
        shutil.move(
            "auto_remediate_setup/data/auto-remediate-settings.json",
            "auto_remediate_setup/data/auto-remediate-settings-backup.json",
        )

        # move mock settings
        shutil.copyfile(
            "auto_remediate_setup/test/data/auto-remediate-settings-deploy.json",
            "auto_remediate_setup/data/auto-remediate-settings.json",
        )

        # create table
        setup.client_dynamodb.create_table(
            TableName="settings-table",
            KeySchema=[{"AttributeName": "key", "KeyType": "HASH"}],
            AttributeDefinitions=[{"AttributeName": "key", "AttributeType": "S"}],
            ProvisionedThroughput={"ReadCapacityUnits": 1, "WriteCapacityUnits": 1},
        )

        # insert settings to DynamoDB
        os.environ["SETTINGSTABLE"] = "settings-table"
        setup.setup_dynamodb()

        # test create_stacks function
        setup.create_stacks("mock_rules", setup.get_settings())

        # validate Stack created
        response = setup.client_cloudformation.list_stacks()
        assert response["StackSummaries"][0]["StackName"] == "cloudtrail-enabled"

        # restore settings
        shutil.move(
            "auto_remediate_setup/data/auto-remediate-settings-backup.json",
            "auto_remediate_setup/data/auto-remediate-settings.json",
        )

        # delete mock_rules directory
        shutil.rmtree("auto_remediate_setup/data/mock_rules")

    # def test_create_stacks_removal(self, setup):
    #     # make mock_rules directory
    #     os.mkdir("auto_remediate_setup/data/mock_rules")

    #     # move mock CloudFormation Stacks
    #     shutil.copyfile(
    #         "auto_remediate_setup/test/data/mock_rules/cloudtrail-enabled.json",
    #         "auto_remediate_setup/data/mock_rules/cloudtrail-enabled.json",
    #     )

    #     # backup settings
    #     shutil.move(
    #         "auto_remediate_setup/data/auto-remediate-settings.json",
    #         "auto_remediate_setup/data/auto-remediate-settings-backup.json",
    #     )

    #     # move mock deploy settings
    #     shutil.copyfile(
    #         "auto_remediate_setup/test/data/auto-remediate-settings-deploy.json",
    #         "auto_remediate_setup/data/auto-remediate-settings.json",
    #     )

    #     # create table
    #     setup.client_dynamodb.create_table(
    #         TableName="settings-table",
    #         KeySchema=[{"AttributeName": "key", "KeyType": "HASH"}],
    #         AttributeDefinitions=[{"AttributeName": "key", "AttributeType": "S"}],
    #         ProvisionedThroughput={"ReadCapacityUnits": 1, "WriteCapacityUnits": 1},
    #     )

    #     # insert settings to DynamoDB
    #     os.environ["SETTINGSTABLE"] = "settings-table"
    #     setup.setup_dynamodb()

    #     # test create_stacks function
    #     setup.create_stacks("mock_rules", setup.get_settings())

    #     # validate Stack created
    #     response = setup.client_cloudformation.list_stacks()
    #     assert response["StackSummaries"][0]["StackName"] == "cloudtrail-enabled"

    #     # move mock remove settings
    #     shutil.copyfile(
    #         "auto_remediate_setup/test/data/auto-remediate-settings-remove.json",
    #         "auto_remediate_setup/data/auto-remediate-settings.json",
    #     )

    #     # insert settings to DynamoDB
    #     setup.setup_dynamodb()

    #     # test create_stacks function
    #     setup.create_stacks("mock_rules", setup.get_settings())

    #     # validate Stack created
    #     response = setup.client_cloudformation.list_stacks()

    #     # restore settings
    #     shutil.move(
    #         "auto_remediate_setup/data/auto-remediate-settings-backup.json",
    #         "auto_remediate_setup/data/auto-remediate-settings.json",
    #     )

    #     # delete mock_rules directory
    #     shutil.rmtree("auto_remediate_setup/data/mock_rules")


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
        os.environ["SETTINGSTABLE"] = "settings-table"

        # create table
        setup.client_dynamodb.create_table(
            TableName="settings-table",
            KeySchema=[{"AttributeName": "key", "KeyType": "HASH"}],
            AttributeDefinitions=[{"AttributeName": "key", "AttributeType": "S"}],
            ProvisionedThroughput={"ReadCapacityUnits": 1, "WriteCapacityUnits": 1},
        )

        # populate table
        setup.client_dynamodb.put_item(
            TableName="settings-table",
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
        os.environ["SETTINGSTABLE"] = "settings-table"

        setup.client_dynamodb.create_table(
            TableName="settings-table",
            KeySchema=[{"AttributeName": "id", "KeyType": "HASH"}],
            AttributeDefinitions=[{"AttributeName": "id", "AttributeType": "S"}],
            ProvisionedThroughput={"ReadCapacityUnits": 1, "WriteCapacityUnits": 1},
        )

        setup.client_dynamodb.put_item(
            TableName="settings-table", Item={"id": {"S": "123"}}
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


class TestSetupDynamoDb:
    @pytest.fixture
    def setup(self):
        with moto.mock_dynamodb2(), moto.mock_sts():
            setup = lambda_handler.Setup(logging)
            yield setup

    def test_setup_dynamodb(self, setup):
        os.environ["SETTINGSTABLE"] = "settings-table"

        # create table
        setup.client_dynamodb.create_table(
            TableName="settings-table",
            KeySchema=[{"AttributeName": "key", "KeyType": "HASH"}],
            AttributeDefinitions=[{"AttributeName": "key", "AttributeType": "S"}],
            ProvisionedThroughput={"ReadCapacityUnits": 1, "WriteCapacityUnits": 1},
        )

        setup.setup_dynamodb()

        assert len(setup.client_dynamodb.scan(TableName="settings-table")["Items"]) > 0

