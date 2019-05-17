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

    @pytest.fixture
    def s3_test_bucket_public_read(self, sh):
        """Creates new publicly readable S3 Bucket
        
        Arguments:
            sh {SecurityHubRules} -- Instance of class SecurityHubRules
        """
        sh.client_s3.create_bucket(ACL="public-read", Bucket="test")
        yield "test"

    @pytest.fixture
    def s3_test_bucket_public_write(self, sh):
        """Creates new publicly writable S3 Bucket
        
        Arguments:
            sh {SecurityHubRules} -- Instance of class SecurityHubRules
        """
        sh.client_s3.create_bucket(ACL="public-read", Bucket="test")
        yield "test"

    def test_s3_bucket_public_read_disabled_check(self, s3_test_bucket_public_read, sh):
        """Tests if S3 Bucket public read has been turned off
        
        Arguments:
            s3_test_bucket_public_read {string} -- S3 bucket name
            sh {SecurityHubRules} -- Instance of class SecurityHubRules
        """
        sh.s3_bucket_public_read_prohibited(s3_test_bucket_public_read)
        response = sh.client_s3.get_bucket_acl(Bucket=s3_test_bucket_public_read)
        assert response["Grants"][0]["Permission"] == "FULL_CONTROL"

    def test_s3_bucket_public_write_disabled_check(
        self, s3_test_bucket_public_write, sh
    ):
        """Tests if S3 Bucket public write has been turned off
        
        Arguments:
            s3_test_bucket_public_write {string} -- S3 bucket name
            sh {SecurityHubRules} -- Instance of class SecurityHubRules
        """
        sh.s3_bucket_public_write_prohibited(s3_test_bucket_public_write)
        response = sh.client_s3.get_bucket_acl(Bucket=s3_test_bucket_public_write)
        assert response["Grants"][0]["Permission"] == "FULL_CONTROL"


class TestSecurityHubS3BucketPublicWriteProhibited:
    @pytest.fixture
    def sh(self):
        with moto.mock_s3():
            sh = security_hub_rules.SecurityHubRules(logging)
            yield sh

    @pytest.fixture
    def s3_test_bucket_public_write(self, sh):
        """Creates new publicly writable S3 Bucket
        
        Arguments:
            sh {SecurityHubRules} -- Instance of class SecurityHubRules
        """
        sh.client_s3.create_bucket(ACL="public-read-write", Bucket="test")
        yield "test"

    def test_s3_bucket_public_write_disabled_check(
        self, s3_test_bucket_public_write, sh
    ):
        """Tests if S3 Bucket public write has been turned off
        
        Arguments:
            s3_test_bucket_public_write {string} -- S3 bucket name
            sh {SecurityHubRules} -- Instance of class SecurityHubRules
        """
        sh.s3_bucket_public_write_prohibited(s3_test_bucket_public_write)
        response = sh.client_s3.get_bucket_acl(Bucket=s3_test_bucket_public_write)
        assert response["Grants"][0]["Permission"] == "FULL_CONTROL"


class TestSecurityHubStatic:
    @pytest.fixture
    def sh(self):
        yield security_hub_rules.SecurityHubRules(logging)

    def test_convert_to_datetime(self, sh):
        assert sh.convert_to_datetime(datetime.date(1999, 12, 31)) == datetime.datetime(
            1999, 12, 31, 0, 0, 0
        )
