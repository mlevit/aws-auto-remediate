import datetime
import logging

import moto
import pytest

from .. import security_hub_rules


class TestSecurityHubS3BucketPublicReadProhibited:
    @pytest.fixture
    def sh(self):
        with moto.mock_s3():
            sh = security_hub_rules.SecurityHubRules(logging)
            yield sh

    def test_s3_bucket_public_read_disabled(self, sh):
        """Tests if S3 Bucket public read has been turned off
        
        Arguments:
            s3_test_bucket_public_read {string} -- S3 bucket name
            sh {SecurityHubRules} -- Instance of class SecurityHubRules
        """

        # create bucket
        sh.client_s3.create_bucket(ACL="public-read", Bucket="test")

        # test s3_bucket_public_read_prohibited function
        sh.s3_bucket_public_read_prohibited("test")

        # validate test
        response = sh.client_s3.get_bucket_acl(Bucket="test")
        assert response["Grants"][0]["Permission"] == "FULL_CONTROL"

    def test_invalid_bucket(self, sh):
        # create bucket
        sh.client_s3.create_bucket(ACL="public-read", Bucket="test")

        # validate test
        assert not sh.s3_bucket_public_read_prohibited("test123")


class TestSecurityHubS3BucketPublicWriteProhibited:
    @pytest.fixture
    def sh(self):
        with moto.mock_s3():
            sh = security_hub_rules.SecurityHubRules(logging)
            yield sh

    def test_s3_bucket_public_write_disabled(self, sh):
        """Tests if S3 Bucket public write has been turned off
        
        Arguments:
            s3_test_bucket_public_write {string} -- S3 bucket name
            sh {SecurityHubRules} -- Instance of class SecurityHubRules
        """

        # create bucket
        sh.client_s3.create_bucket(ACL="public-read", Bucket="test")

        # test s3_bucket_public_read_prohibited function
        sh.s3_bucket_public_write_prohibited("test")

        # validate test
        response = sh.client_s3.get_bucket_acl(Bucket="test")
        assert response["Grants"][0]["Permission"] == "FULL_CONTROL"

    def test_invalid_bucket(self, sh):
        # create bucket
        sh.client_s3.create_bucket(ACL="public-read", Bucket="test")

        # validate test
        assert not sh.s3_bucket_public_write_prohibited("test123")


class TestSecurityHubStatic:
    @pytest.fixture
    def sh(self):
        yield security_hub_rules.SecurityHubRules(logging)

    def test_convert_to_datetime(self, sh):
        assert sh.convert_to_datetime(datetime.date(1999, 12, 31)) == datetime.datetime(
            1999, 12, 31, 0, 0, 0
        )
