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
    def kms_test_key_id(self, sh):
        """Creates new KMS Customer Managed Key
        
        Arguments:
            sh {SecurityHubRules} -- Instance of class SecurityHubRules
        """
        res = sh.client_kms.create_key()
        yield res["KeyMetadata"]["KeyId"]

    def test_kms_cmk_backing_key_rotation_enabled_check(self, kms_test_key_id, sh):
        """Tests if KMS Customer Managed Key rotation is turned on
        
        Arguments:
            kms_test_key_id {string} -- KMS CMK ID
            sh {SecurityHubRules} -- Instance of class SecurityHubRules
        """
        sh.cmk_backing_key_rotation_enabled(kms_test_key_id)
        response = sh.client_kms.get_key_rotation_status(KeyId=kms_test_key_id)
        assert response["KeyRotationEnabled"]


class TestSecurityHubStatic:
    @pytest.fixture
    def sh(self):
        yield security_hub_rules.SecurityHubRules(logging)

    def test_convert_to_datetime(self, sh):
        assert sh.convert_to_datetime(datetime.date(1999, 12, 31)) == datetime.datetime(
            1999, 12, 31, 0, 0, 0
        )
