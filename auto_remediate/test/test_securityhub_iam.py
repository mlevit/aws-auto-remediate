import pytest
import moto
from .. import security_hub_rules
import logging
import datetime


class TestSecurityHubIamUserNoPoliciesCheck:
    @pytest.fixture
    def sh(self):
        with moto.mock_ec2(), moto.mock_s3(), moto.mock_iam(), moto.mock_kms():
            sh = security_hub_rules.SecurityHubRules(logging)
            yield sh

    @pytest.fixture
    def iam_test_user_id(self, sh):
        response = sh.client_iam.create_user(UserName="test")
        yield response["User"]["UserId"]

    @pytest.fixture
    def iam_test_user_with_policy(self, iam_test_user_id, sh):
        """
        Sets up a user with attached user policy to test iam_no_user_policies_check
        """
        sh.client_iam.attach_user_policy(
            UserName="test", PolicyArn="arn:aws:iam::aws:policy/IAMReadOnlyAccess"
        )
        yield sh

    def test_iam_no_user_policies_check(
        self, iam_test_user_id, iam_test_user_with_policy
    ):
        iam_test_user_with_policy.iam_user_no_policies_check(iam_test_user_id)
        response = iam_test_user_with_policy.client_iam.list_attached_user_policies(
            UserName="test"
        )
        assert not response["AttachedPolicies"]


class TestSecurityHubMfaEnabledForIamConsoleAccess:
    """
    Tests that the remediation removes a login profile from a user
    """

    @pytest.fixture
    def sh(self):
        with moto.mock_iam():
            sh = security_hub_rules.SecurityHubRules(logging)
            yield sh

    @pytest.fixture
    def iam_test_user_id(self, sh):
        response = sh.client_iam.create_user(UserName="test")
        yield response["User"]["UserId"]

    @pytest.fixture
    def iam_test_user_login_profile(self, iam_test_user_id, sh):
        sh.client_iam.create_login_profile(UserName="test", Password="!@#$QWERasdf1234")
        yield sh

    def test_securityhub_mfa_enabled_for_iam_console_access(
        self, iam_test_user_login_profile, iam_test_user_id
    ):
        # before remediation, user must have login profile
        assert iam_test_user_login_profile.client_iam.get_login_profile(UserName="test")

        # run remediation
        iam_test_user_login_profile.mfa_enabled_for_iam_console_access(
            resource_id=iam_test_user_id
        )

        # assert user doesn't have login profile after remediation
        with pytest.raises(
            iam_test_user_login_profile.client_iam.exceptions.NoSuchEntityException
        ):
            iam_test_user_login_profile.client_iam.get_login_profile(UserName="test")


class TestSecurityHubStatic:
    @pytest.fixture
    def sh(self):
        yield security_hub_rules.SecurityHubRules(logging)

    def test_convert_to_datetime(self, sh):
        assert sh.convert_to_datetime(datetime.date(1999, 12, 31)) == datetime.datetime(
            1999, 12, 31, 0, 0, 0
        )
