import datetime
import logging

import moto
import pytest

from .. import config_rules


class TestRdsInstancePublicAccessCheck:
    @pytest.fixture
    def cr(self):
        with moto.mock_rds():
            cr = config_rules.ConfigRules(logging)
            yield cr

    def test_invalid_rds(self, cr):
        # validate test
        assert not cr.rds_instance_public_access_check("test")
