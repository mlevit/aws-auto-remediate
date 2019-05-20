import datetime
import logging

import moto
import pytest

from .. import security_hub_rules


class TestSecurityHubCmkBackingKeyRotationEnabled:
    @pytest.fixture
    def sh(self):
        with moto.mock_kms(), moto.mock_sts():
            sh = security_hub_rules.SecurityHubRules(logging)
            yield sh

    def test_kms_cmk_rotation_enabled(self, sh):
        """Tests if KMS Customer Managed Key rotation is turned on
        
        Arguments:
            sh {SecurityHubRules} -- Instance of class SecurityHubRules
        """

        # create KMS CMK
        response = sh.client_kms.create_key()
        kms_key_id = response["KeyMetadata"]["KeyId"]

        # test cmk_backing_key_rotation_enabled
        sh.cmk_backing_key_rotation_enabled(kms_key_id)

        # validate test
        response = sh.client_kms.get_key_rotation_status(KeyId=kms_key_id)
        assert response["KeyRotationEnabled"]

    def test_invalid_invalid_kms_cmk(self, sh):
        """Tests invalid KMS CMK
        
        Arguments:
            sh {SecurityHubRules} -- Instance of class SecurityHubRules
        """
        # test cmk_backing_key_rotation_enabled
        response = sh.cmk_backing_key_rotation_enabled(
            "e85f5843-1111-4bcb-b711-7e17fa181804"
        )
        assert not response
