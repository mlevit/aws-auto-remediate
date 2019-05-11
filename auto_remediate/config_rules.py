import boto3
import sys


class ConfigRules:
    def __init__(self, logging):
        self.logging = logging

    def rds_instance_public_access_check(self, resource_id):
        """
        Sets PubliclyAccessible field to False.
        """
        client = boto3.client("rds")

        # unfortunately the resourceId provided by AWS Config is DbiResourceId
        # and cannot be used in the modify_db_instance function
        # we therefore need to search all RDS instances
        try:
            response = client.describe_db_instances()

            for instance in response.get("DBInstances"):
                if resource_id == instance.get("DbiResourceId"):
                    client.modify_db_instance(
                        DBInstanceIdentifier=instance.get("DBInstanceIdentifier"),
                        PubliclyAccessible=False,
                    )
                    break

            self.logging.info(
                f"Disabled Public Accessibility for RDS Resource ID '{resource_id}'."
            )
            return True
        except:
            self.logging.error(
                f"Could not disable Public Accessibility for RDS Resource ID '{resource_id}'."
            )
            self.logging.error(sys.exc_info()[1])
            return False
