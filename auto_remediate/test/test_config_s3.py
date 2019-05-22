import datetime
import logging

import moto
import pytest

from .. import config_rules

# s3_bucket_server_side_encryption_enabled
class TestS3BucketServerSideEncryptionEnabledCheck:
    @pytest.fixture
    def cr(self):
        with moto.mock_s3():
            cr = config_rules.ConfigRules(logging)
            yield cr

    # def test_s3_bucket_sse_enabled(self, cr):
    #     # create bucket
    #     cr.client_s3.create_bucket(Bucket="test")

    #     # test s3_bucket_server_side_encryption_enabled function
    #     cr.s3_bucket_server_side_encryption_enabled("test")

    #     # validate test
    #     response = cr.client_s3.get_bucket_encryption(Bucket="test")
    #     print(response)
    #     assert (
    #         response["ServerSideEncryptionConfiguration"]["Rules"][0][
    #             "ApplyServerSideEncryptionByDefault"
    #         ]["SSEAlgorithm"]
    #         == "AES256"
    #     )

    # def test_invalid_bucket(self, cr):
    #     # create bucket
    #     cr.client_s3.create_bucket(Bucket="test")

    #     # validate test
    #     assert not cr.s3_bucket_server_side_encryption_enabled("test123")
