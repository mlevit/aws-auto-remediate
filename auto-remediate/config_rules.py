import boto3
import sys


class ConfigRules:
    def __init__(self, logging):
        self.logging = logging

    def rds_instance_public_access_check(self, record):
        """
        Sets PubliclyAccessible field to False.
        """
        client = boto3.client('rds')
        resource_id = record.get('detail').get('resourceId')

        # unfortunately the resourceId provided by AWS Config is DbiResourceId
        # and cannot be used in the modify_db_instance function
        # we therefore need to search all RDS instances
        try:
            response = client.describe_db_instances()

            for instance in response.get('DBInstances'):
                if resource_id == instance.get('DbiResourceId'):
                    client.modify_db_instance(
                        DBInstanceIdentifier=instance.get('DBInstanceIdentifier'),
                        PubliclyAccessible=False)
                    break

            self.logging.info("Disabled Public Accessibility for RDS Resource ID '%s'." % resource_id)
            return True
        except:
            self.logging.error("Could not disable Public Accessibility for RDS Resource ID '%s'." % resource_id)
            self.logging.error(sys.exc_info()[1])
            return False