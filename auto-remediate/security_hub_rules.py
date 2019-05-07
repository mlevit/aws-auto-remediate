import boto3
import sys


class SecurityHubRules:
    def __init__(self, logging):
        self.logging = logging
    
    def access_keys_rotated(self, record):
        """
        Deletes IAM User's access and secret key.
        """
        # TODO Access Keys Rotated rule needs testing
        # client = boto3.client('iam')
        # resource_id = None
        
        # try:
        #     client.delete_access_key(AccessKeyId=resource_id)
            
        #     self.logging.info("Deleted unrotated IAM Access Key '%s'." % resource_id)
        #     return True
        # except:
        #     self.logging.info("Could not delete unrotated IAM Access Key '%s'." % resource_id)
        #     self.logging.error(sys.exc_info()[1])
        #     return False
        pass
    
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
            self.logging.error(sys.exc_info()[1])
            return False