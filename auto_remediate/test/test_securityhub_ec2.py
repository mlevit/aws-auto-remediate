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

    def test_rdp_port_statements_removed(self, sh):
        """Tests removal of RDP statements from Security Group
        
        Arguments:
            sh {SecurityHubRules} -- Instance of SecurityHubRules class
        """

        # create Security Group
        response = sh.client_ec2.create_security_group(
            Description="test", GroupName="test"
        )
        security_group_id = response["GroupId"]

        # attach statements to Security Group
        sh.client_ec2.authorize_security_group_ingress(
            GroupId=security_group_id,
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

        # test restricted_rdp function
        sh.restricted_rdp(security_group_id)

        # validate test
        response = sh.client_ec2.describe_security_groups(GroupIds=[security_group_id])
        assert len(response["SecurityGroups"][0]["IpPermissions"]) == 0

    def test_non_rdp_port_statements_not_removed(self, sh):
        """Tests non-RDP port statements are not removed from the Security Group
        
        Arguments:
            sh {SecurityHubRules} -- Instance of SecurityHubRules class
        """

        # create Security Group
        response = sh.client_ec2.create_security_group(
            Description="test", GroupName="test"
        )
        security_group_id = response["GroupId"]

        # attach statements to Security Group
        sh.client_ec2.authorize_security_group_ingress(
            GroupId=security_group_id,
            IpPermissions=[
                {
                    "FromPort": 1234,
                    "ToPort": 1234,
                    "IpProtocol": "tcp",
                    "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
                },
                {
                    "FromPort": 1234,
                    "ToPort": 1234,
                    "IpProtocol": "tcp",
                    "Ipv6Ranges": [{"CidrIpv6": "::/0"}],
                },
            ],
        )

        # test restricted_rdp function
        sh.restricted_rdp(security_group_id)

        # validate test
        response = sh.client_ec2.describe_security_groups(GroupIds=[security_group_id])
        assert len(response["SecurityGroups"][0]["IpPermissions"]) == 2


class TestSecurityHubRestrictedSSHCheck:
    @pytest.fixture
    def sh(self):
        with moto.mock_ec2():
            sh = security_hub_rules.SecurityHubRules(logging)
            yield sh

    def test_ssh_port_statements_removed(self, sh):
        """Tests removal of SSH statements from Security Group
        
        Arguments:
            sh {SecurityHubRules} -- Instance of SecurityHubRules class
        """
        # create Security Group
        response = sh.client_ec2.create_security_group(
            Description="test", GroupName="test"
        )
        security_group_id = response["GroupId"]

        # attach statements to Security Group
        sh.client_ec2.authorize_security_group_ingress(
            GroupId=security_group_id,
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

        # test restricted_rdp function
        sh.restricted_ssh(security_group_id)

        # validate test
        response = sh.client_ec2.describe_security_groups(GroupIds=[security_group_id])
        assert len(response["SecurityGroups"][0]["IpPermissions"]) == 0

    def test_non_ssh_port_statements_not_removed(self, sh):
        """Tests non-SSH port statements are not removed from the Security Group
        
        Arguments:
            sh {SecurityHubRules} -- Instance of SecurityHubRules class
        """

        # create Security Group
        response = sh.client_ec2.create_security_group(
            Description="test", GroupName="test"
        )
        security_group_id = response["GroupId"]

        # attach statements to Security Group
        sh.client_ec2.authorize_security_group_ingress(
            GroupId=security_group_id,
            IpPermissions=[
                {
                    "FromPort": 1234,
                    "ToPort": 1234,
                    "IpProtocol": "tcp",
                    "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
                },
                {
                    "FromPort": 1234,
                    "ToPort": 1234,
                    "IpProtocol": "tcp",
                    "Ipv6Ranges": [{"CidrIpv6": "::/0"}],
                },
            ],
        )

        # test restricted_rdp function
        sh.restricted_ssh(security_group_id)

        # validate test
        response = sh.client_ec2.describe_security_groups(GroupIds=[security_group_id])
        assert len(response["SecurityGroups"][0]["IpPermissions"]) == 2


class TestSecurityHubVPCDefaultSecurityGroupClosedCheck:
    @pytest.fixture
    def sh(self):
        with moto.mock_ec2():
            sh = security_hub_rules.SecurityHubRules(logging)
            yield sh

    @pytest.fixture
    def security_group_id(self, sh):
        """Creates EC2 Security Group
        
        Arguments:
            sh {SecurityHubRules} -- Instance of SecurityHubRules class
        """
        response = sh.client_ec2.create_security_group(
            Description="test", GroupName="test"
        )
        yield response["GroupId"]

    def test_ingress_statements_removed(self, sh, security_group_id):
        """Tests ingress statements are removed from Security Group
        
        Arguments:
            sh {SecurityHubRules} -- Instance of SecurityHubRules class
            security_group_id {string} -- EC2 Security Group ID
        """

        # attach ingress Statements to Security Group
        sh.client_ec2.authorize_security_group_ingress(
            GroupId=security_group_id,
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
            ],
        )

        # test vpc_default_security_group_closed function
        sh.vpc_default_security_group_closed(security_group_id)

        # validate test
        response = sh.client_ec2.describe_security_groups(GroupIds=[security_group_id])
        assert len(response["SecurityGroups"][0]["IpPermissions"]) == 0

    def test_egress_statements_removed(self, sh, security_group_id):
        """Tests egress statements are removed from Security Group
        
        Arguments:
            sh {SecurityHubRules} -- Instance of SecurityHubRules class
            security_group_id {string} -- EC2 Security Group ID
        """

        # attach egress Statements to Security Group
        sh.client_ec2.authorize_security_group_egress(
            GroupId=security_group_id,
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
            ],
        )

        # test vpc_default_security_group_closed function
        sh.vpc_default_security_group_closed(security_group_id)

        # validate test
        response = sh.client_ec2.describe_security_groups(GroupIds=[security_group_id])
        assert len(response["SecurityGroups"][0]["IpPermissionsEgress"]) == 0

    def test_invalid_security_group_id(self, sh):
        assert not sh.vpc_default_security_group_closed("test")
