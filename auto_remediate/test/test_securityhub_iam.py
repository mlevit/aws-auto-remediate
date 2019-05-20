import datetime
import logging

import moto
import pytest

from .. import security_hub_rules


class TestSecurityHubAccessKeysRotatedCheck:
    @pytest.fixture
    def sh(self):
        with moto.mock_iam():
            sh = security_hub_rules.SecurityHubRules(logging)
            yield sh

    @pytest.fixture
    def iam_test_user_name(self, sh):
        response = sh.client_iam.create_user(UserName="test")
        yield response["User"]["UserName"]

    @pytest.fixture
    def iam_test_access_key_id(self, iam_test_user_name, sh):
        response = sh.client_iam.create_access_key(UserName=iam_test_user_name)
        yield response["AccessKey"]["AccessKeyId"]

    def test_access_key_rotated_check(
        self, iam_test_user_name, iam_test_access_key_id, sh
    ):
        sh.access_keys_rotated(iam_test_access_key_id)
        response = sh.client_iam.list_access_keys(UserName=iam_test_user_name)
        assert not response["AccessKeyMetadata"]

    def test_iam_user_name_not_found_check(self, sh):
        """Tests if an error is thrown if the Access Key ID cannot be found
        
        Arguments:
            sh {SecurityHubRules} -- Instance of SecurityHubRules class
        """
        assert not sh.access_keys_rotated("FAKE_KEY_ID")


class TestSecurityHubIamPolicyNoStatementsWithAdminAccessCheck:
    @pytest.fixture
    def sh(self):
        with moto.mock_iam():
            sh = security_hub_rules.SecurityHubRules(logging)
            yield sh

    @pytest.fixture
    def iam_test_policy_arn(self, sh):
        """Creates new IAM Policy with admin access
        
        Arguments:
            sh {SecurityHubRules} -- Instance of SecurityHubRules class
        """
        response = sh.client_iam.create_policy(
            PolicyName="test",
            PolicyDocument='{"Version":"2012-10-17","Statement":[{"Sid":"Test","Effect":"Allow","Action":"*","Resource":"*"}]}',
        )
        yield response["Policy"]["Arn"]

    @pytest.fixture
    def iam_test_policy_id(self, iam_test_policy_arn, sh):
        """Retrieves IAM Policy ID from IAM Policy ARN
        
        Arguments:
            iam_test_policy_arn {string} -- IAM Policy ARN
            sh {SecurityHubRules} -- Instance of SecurityHubRules class
        """
        response = sh.client_iam.get_policy(PolicyArn=iam_test_policy_arn)
        yield response["Policy"]["PolicyId"]

    def test_securityhub_iam_policy_no_statement_with_admin_access_check(
        self, iam_test_policy_arn, iam_test_policy_id, sh
    ):
        """Tests if an IAM Policy Statement with admin access is removed
        
        Arguments:
            iam_test_policy_arn {string} -- IAM Policy ARN
            iam_test_policy_id {string} -- IAM Policy ID
            sh {SecurityHubRules} -- Instance of SecurityHubRules class
        """
        # call remediation function to remove IAM Policy Statement with admin access
        sh.iam_policy_no_statements_with_admin_access(iam_test_policy_id)

        # get IAM Policy Default Version
        response = sh.client_iam.get_policy(PolicyArn=iam_test_policy_arn)
        iam_test_policy_default_version = response.get("Policy").get("DefaultVersionId")

        # get IAM Policy Version that includes Policy Statement
        response = sh.client_iam.get_policy_version(
            PolicyArn=iam_test_policy_arn, VersionId=iam_test_policy_default_version
        )

        assert len(response["PolicyVersion"]["Document"]["Statement"]) == 0


class TestSecurityHubIamUserNoPoliciesCheck:
    @pytest.fixture
    def sh(self):
        with moto.mock_ec2(), moto.mock_s3(), moto.mock_iam(), moto.mock_kms():
            sh = security_hub_rules.SecurityHubRules(logging)
            yield sh

    @pytest.fixture
    def iam_test_user_id(self, sh):
        """Creates IAM User
        
        Arguments:
            sh {SecurityHubRules} -- Instance of SecurityHubRules class
        """
        response = sh.client_iam.create_user(UserName="test")
        yield response["User"]["UserId"]

    @pytest.fixture
    def iam_test_user_with_policy(self, iam_test_user_id, sh):
        """Sets up a user with attached user policy to test iam_no_user_policies_check
        
        Arguments:
            iam_test_user_id {string} -- IAM User ID
            sh {SecurityHubRules} -- Instance of SecurityHubRules class
        """
        sh.client_iam.attach_user_policy(
            UserName="test", PolicyArn="arn:aws:iam::aws:policy/IAMReadOnlyAccess"
        )
        yield sh

    def test_iam_no_user_policies_check(
        self, iam_test_user_id, iam_test_user_with_policy
    ):
        """Tests that IAM Managed Policies are removed from an IAM User
        
        Arguments:
            iam_test_user_id {string} -- IAM User ID
            iam_test_user_with_policy {function} -- Instance of a function
        """
        iam_test_user_with_policy.iam_user_no_policies_check(iam_test_user_id)
        response = iam_test_user_with_policy.client_iam.list_attached_user_policies(
            UserName="test"
        )
        assert not response["AttachedPolicies"]


class TestSecurityHubMfaEnabledForIamConsoleAccess:
    @pytest.fixture
    def sh(self):
        with moto.mock_iam():
            sh = security_hub_rules.SecurityHubRules(logging)
            yield sh

    @pytest.fixture
    def iam_test_user_id(self, sh):
        """Creates IAM User
        
        Arguments:
            sh {SecurityHubRules} -- Instance of SecurityHubRules class
        """
        response = sh.client_iam.create_user(UserName="test")
        yield response["User"]["UserId"]

    @pytest.fixture
    def iam_test_user_login_profile(self, iam_test_user_id, sh):
        """Creates a Login Profile for an IAM User
        
        Arguments:
            iam_test_user_id {string} -- IAM User ID
            sh {SecurityHubRules} -- Instance of SecurityHubRules class
        """
        sh.client_iam.create_login_profile(UserName="test", Password="!@#$QWERasdf1234")
        yield sh

    def test_securityhub_mfa_enabled_for_iam_console_access_check(
        self, iam_test_user_login_profile, iam_test_user_id
    ):
        """Tests that the remediation removes a login profile from a user
        
        Arguments:
            iam_test_user_login_profile {function} -- Instance of function
            iam_test_user_id {string} -- IAM User ID
        """
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
