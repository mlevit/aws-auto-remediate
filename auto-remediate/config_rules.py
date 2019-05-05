import boto3
import sys


class ConfigRules:
    def __init__(self, logging):
        self.logging = logging
    
    def access_keys_rotated(self, record):
        """
        Deletes IAM User's access and secret key.
        """
        # TODO Access Keys Rotated rule needs testing
        client = boto3.client('iam')
        resource_id = None
        
        try:
            client.delete_access_key(AccessKeyId=resource_id)
            
            self.logging.info("Deleted unrotated IAM Access Key '%s'." % resource_id)
            return True
        except:
            self.logging.info("Could not delete unrotated IAM Access Key '%s'." % resource_id)
            self.logging.error(sys.exc_info())
            return False

    def restricted_ssh(self, record):
        """
        Deletes inbound rules within Security Groups that match:
            Protocal: TCP
            Port: 22
            Source: 0.0.0.0/0 or ::/0
        """
        client = boto3.client('ec2')
        resource_id = record.get('detail').get('resourceId')
        
        try:
            client.revoke_security_group_ingress(
                GroupId=resource_id,
                IpPermissions=[
                    {
                        'FromPort': 22,
                        'ToPort': 22,
                        'IpProtocol': 'tcp',
                        'IpRanges': [{'CidrIp': '0.0.0.0/0'}]
                    },
                    {
                        'FromPort': 22,
                        'ToPort': 22,
                        'IpProtocol': 'tcp',
                        'Ipv6Ranges': [{'CidrIpv6': '::/0'}]
                    }
                ]
            )

            self.logging.info("Revoked public port 22 ingress rule for Security Group '%s'." % resource_id)
            return True
        except:
            self.logging.error("Could not revoke public port 22 ingress rule for Security Group '%s'." % resource_id)
            self.logging.error(sys.exc_info())
            return False

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
                    # TODO need to validate state of instance
                    client.modify_db_instance(
                        DBInstanceIdentifier=instance.get('DBInstanceIdentifier'),
                        PubliclyAccessible=False)
                    break

            self.logging.info("Disabled Public Accessibility for RDS Resource ID '%s'." % resource_id)
            return True
        except:
            self.logging.error("Could not disable Public Accessibility for RDS Resource ID '%s'." % resource_id)
            self.logging.error(sys.exc_info())
            return False