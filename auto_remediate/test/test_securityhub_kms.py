import pytest
import moto
from .. import security_hub_rules
import logging
import datetime


class TestSecurityHubCmkBackingKeyRotationEnabled:
    @pytest.fixture
    def sh(self):
        with moto.mock_kms(), moto.mock_sts():
            sh = security_hub_rules.SecurityHubRules(logging)
            yield sh

    @pytest.fixture
    def iam_test_key_id(self, sh):
        res = sh.client_kms.create_key()
        yield res["KeyMetadata"]["KeyId"]

    @pytest.fixture
    def iam_test_kms_with_no_rotation(self, iam_test_key_id, sh):
        """
        Sets up a user with attached user policy to test iam_no_user_policies_check
        """
        yield sh

    def test_kms_cmk_backing_key_ration_enabled_check(
        self, iam_test_key_id, iam_test_kms_with_no_rotation
    ):
        iam_test_kms_with_no_rotation.cmk_backing_key_rotation_enabled(iam_test_key_id)
        rotation_status = iam_test_kms_with_no_rotation.client_kms.get_key_rotation_status(
            KeyId=iam_test_key_id
        )
        assert rotation_status["KeyRotationEnabled"]


class TestSecurityHubStatic:
    @pytest.fixture
    def sh(self):
        yield security_hub_rules.SecurityHubRules(logging)

    def test_convert_to_datetime(self, sh):
        assert sh.convert_to_datetime(datetime.date(1999, 12, 31)) == datetime.datetime(
            1999, 12, 31, 0, 0, 0
        )
