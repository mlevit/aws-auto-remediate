import boto3
import sys


class ConfigRules:
    def __init__(self, logging):
        self.logging = logging
    
    
    def access_keys_rotated(self, record):
        """
        Deletes IAM User's access and secret key
        """
        pass
    

    def restricted_ssh(self, record):
        """
        Deletes inbound rules within Security Groyps that match:
            Protocal: TCP
            Port: 22
            Source: 0.0.0.0/0 or ::/0
        """

        client = boto3.client('ec2')
        security_group_id = record.get('detail').get('resourceId')
        
        try:
            client.revoke_security_group_ingress(
                GroupId=security_group_id,
                IpPermissions=[
                    {
                        'FromPort': 22,
                        'ToPort': 22,
                        'IpProtocol': 'tcp',
                        'IpRanges': [{'CidrIp': '0.0.0.0/0'},]
                    },
                    {
                        'FromPort': 22,
                        'ToPort': 22,
                        'IpProtocol': 'tcp',
                        'Ipv6Ranges': [{'CidrIpv6': '::/0'},]
                    }
                ]
            )

            self.logging.info("Revoked public port 22 ingress rule for Security Group '%s'." % security_group_id)
        except:
            self.logging.error("Could not revoke public port 22 ingress rule for Security Group '%s'." % security_group_id)
            self.logging.error(str(sys.exc_info()))