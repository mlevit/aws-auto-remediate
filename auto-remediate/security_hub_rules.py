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
    
    def restricted_rdp(self, resource_id):
        """
        Deletes inbound rules within Security Groups that match:
            Protocol: TCP
            Port: 3389
            Source: 0.0.0.0/0 or ::/0
        """
        client = boto3.client('ec2')
        
        try:
            client.revoke_security_group_ingress(
                GroupId=resource_id,
                IpPermissions=[
                    {
                        'FromPort': 3389,
                        'ToPort': 3389,
                        'IpProtocol': 'tcp',
                        'IpRanges': [{'CidrIp': '0.0.0.0/0'}]
                    },
                    {
                        'FromPort': 3389,
                        'ToPort': 3389,
                        'IpProtocol': 'tcp',
                        'Ipv6Ranges': [{'CidrIpv6': '::/0'}]
                    }
                ]
            )

            self.logging.info("Revoked public port 3389 ingress rule for Security Group '%s'." % resource_id)
            return True
        except:
            self.logging.error("Could not revoke public port 3389 ingress rule for Security Group '%s'." % resource_id)
            self.logging.error(sys.exc_info()[1])
            return False
    
    def restricted_ssh(self, resource_id):
        """
        Deletes inbound rules within Security Groups that match:
            Protocol: TCP
            Port: 22
            Source: 0.0.0.0/0 or ::/0
        """
        client = boto3.client('ec2')
        
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
    
    def s3_bucket_public_read_prohibited(self, resource_id):
        """
        Sets the S3 Bucket ACL to private to prevent public read.
        """
        client = boto3.client('s3')
        
        try:
            client.put_bucket_acl(
                ACL='private',
                Bucket=resource_id)

            self.logging.info("ACL set to 'private' for S3 Bucket '%s'." % resource_id)
            return True
        except:
            self.logging.info("Could not set ACL set to 'private' for S3 Bucket '%s'." % resource_id)
            self.logging.error(sys.exc_info()[1])
            return False
    
    def s3_bucket_public_write_prohibited(self, resource_id):
        """
        Sets the S3 Bucket ACL to private to prevent public write.
        """
        client = boto3.client('s3')
        
        try:
            client.put_bucket_acl(
                ACL='private',
                Bucket=resource_id)

            self.logging.info("ACL set to 'private' for S3 Bucket '%s'." % resource_id)
            return True
        except:
            self.logging.info("Could not set ACL set to 'private' for S3 Bucket '%s'." % resource_id)
            self.logging.error(sys.exc_info()[1])
            return False