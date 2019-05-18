import datetime
import logging

import moto
import pytest

from .. import security_hub_rules


class TestSecurityHubRestrictedRDPCheck:
    @pytest.fixture
    def sh(self):
        with moto.mock_ec2():
            sh = security_hub_rules.SecurityHubRules(logging)
            yield sh

    @pytest.fixture
    def ec2_test_security_group_id(self, sh):
        response = sh.client_ec2.create_security_group(
            Description="test", GroupName="test"
        )
        yield response["GroupId"]

    @pytest.fixture
    def ec2_test_security_group_with_non_restricted_rdp(
        self, ec2_test_security_group_id, sh
    ):
        sh.client_ec2.authorize_security_group_ingress(
            GroupId=ec2_test_security_group_id,
            IpPermissions=[
                {
                    "FromPort": 3389,
                    "ToPort": 3389,
                    "IpProtocol": "tcp",
                    "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
                },
                {
                    "FromPort": 3389,
                    "ToPort": 3389,
                    "IpProtocol": "tcp",
                    "Ipv6Ranges": [{"CidrIpv6": "::/0"}],
                },
            ],
        )
        yield sh

    def test_ec2_security_group_restricted_rdp_check(
        self,
        ec2_test_security_group_id,
        ec2_test_security_group_with_non_restricted_rdp,
    ):
        ec2_test_security_group_with_non_restricted_rdp.restricted_rdp(
            ec2_test_security_group_id
        )
        response = ec2_test_security_group_with_non_restricted_rdp.client_ec2.describe_security_groups(
            GroupIds=[ec2_test_security_group_id]
        )
        assert len(response["SecurityGroups"][0]["IpPermissions"]) == 0


class TestSecurityHubRestrictedSSHCheck:
    @pytest.fixture
    def sh(self):
        with moto.mock_ec2():
            sh = security_hub_rules.SecurityHubRules(logging)
            yield sh

    @pytest.fixture
    def ec2_test_security_group_id(self, sh):
        response = sh.client_ec2.create_security_group(
            Description="test", GroupName="test"
        )
        yield response["GroupId"]

    @pytest.fixture
    def ec2_test_security_group_with_non_restricted_ssh(
        self, ec2_test_security_group_id, sh
    ):
        sh.client_ec2.authorize_security_group_ingress(
            GroupId=ec2_test_security_group_id,
            IpPermissions=[
                {
                    "FromPort": 22,
                    "ToPort": 22,
                    "IpProtocol": "tcp",
                    "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
                },
                {
                    "FromPort": 22,
                    "ToPort": 22,
                    "IpProtocol": "tcp",
                    "Ipv6Ranges": [{"CidrIpv6": "::/0"}],
                },
            ],
        )
        yield sh

    def test_ec2_security_group_restricted_ssh_check(
        self,
        ec2_test_security_group_id,
        ec2_test_security_group_with_non_restricted_ssh,
    ):
        ec2_test_security_group_with_non_restricted_ssh.restricted_ssh(
            ec2_test_security_group_id
        )
        response = ec2_test_security_group_with_non_restricted_ssh.client_ec2.describe_security_groups(
            GroupIds=[ec2_test_security_group_id]
        )
        assert len(response["SecurityGroups"][0]["IpPermissions"]) == 0


class TestSecurityHubVPCDefaultSecurityGroupClosedCheck:
    @pytest.fixture
    def sh(self):
        with moto.mock_ec2():
            sh = security_hub_rules.SecurityHubRules(logging)
            yield sh

    @pytest.fixture
    def ec2_test_security_group_id(self, sh):
        """Creates EC2 Security Grou[]
        
        Arguments:
            sh {SecurityHubRules} -- Instance of SecurityHubRules class
        """
        response = sh.client_ec2.create_security_group(
            Description="test", GroupName="test"
        )
        yield response["GroupId"]

    @pytest.fixture
    def ec2_test_security_group_with_rules(self, ec2_test_security_group_id, sh):
        """Adds ingress and egress rules to an EC2 Security Group ID
        
        Arguments:
            ec2_test_security_group_id {string} -- EC2 Security Group ID
            sh {SecurityHubRules} -- Instance of SecurityHubRules class
        """
        # create ingress rules
        sh.client_ec2.authorize_security_group_ingress(
            GroupId=ec2_test_security_group_id,
            IpPermissions=[
                {
                    "FromPort": 22,
                    "ToPort": 22,
                    "IpProtocol": "tcp",
                    "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
                },
                {
                    "FromPort": 80,
                    "ToPort": 80,
                    "IpProtocol": "tcp",
                    "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
                },
                {
                    "FromPort": 8080,
                    "ToPort": 8080,
                    "IpProtocol": "tcp",
                    "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
                },
                {
                    "FromPort": 443,
                    "ToPort": 443,
                    "IpProtocol": "tcp",
                    "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
                },
            ],
        )
        
        # create egress rules
        sh.client_ec2.authorize_security_group_egress(
            GroupId=ec2_test_security_group_id,
            IpPermissions=[
                {
                    "FromPort": 22,
                    "ToPort": 22,
                    "IpProtocol": "tcp",
                    "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
                },
                {
                    "FromPort": 80,
                    "ToPort": 80,
                    "IpProtocol": "tcp",
                    "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
                },
                {
                    "FromPort": 8080,
                    "ToPort": 8080,
                    "IpProtocol": "tcp",
                    "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
                },
                {
                    "FromPort": 443,
                    "ToPort": 443,
                    "IpProtocol": "tcp",
                    "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
                },
            ],
        )
        yield sh

    def test_ec2_security_group_closed_check(
        self, ec2_test_security_group_id, ec2_test_security_group_with_rules
    ):
        ec2_test_security_group_with_rules.vpc_default_security_group_closed(
            ec2_test_security_group_id
        )
        response = ec2_test_security_group_with_rules.client_ec2.describe_security_groups(
            GroupIds=[ec2_test_security_group_id]
        )
        assert len(response["SecurityGroups"][0]["IpPermissions"]) == 0
        assert len(response["SecurityGroups"][0]["IpPermissionsEgress"]) == 0


class TestSecurityHubStatic:
    @pytest.fixture
    def sh(self):
        yield security_hub_rules.SecurityHubRules(logging)

    def test_convert_to_datetime(self, sh):
        assert sh.convert_to_datetime(datetime.date(1999, 12, 31)) == datetime.datetime(
            1999, 12, 31, 0, 0, 0
        )
