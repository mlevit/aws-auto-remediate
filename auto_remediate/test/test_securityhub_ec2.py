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
        self.client_ec2.authorize_security_group_ingress(
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
        assert len(response["SecurityGroups"]["IpPermissions"]) == 0


class TestSecurityHubStatic:
    @pytest.fixture
    def sh(self):
        yield security_hub_rules.SecurityHubRules(logging)

    def test_convert_to_datetime(self, sh):
        assert sh.convert_to_datetime(datetime.date(1999, 12, 31)) == datetime.datetime(
            1999, 12, 31, 0, 0, 0
        )
