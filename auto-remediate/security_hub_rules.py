import boto3
import datetime
import dateutil.parser
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
    
    def iam_password_policy(self, resource_id):
        """
        Applies a sensible IAM password policy, as per CIS AWS Foundations Standard Checks Supported in Security Hub
        1.5 - Ensure IAM password policy requires at least one uppercase letter
        1.6 - Ensure IAM password policy requires at least one lowercase letter
        1.7 - Ensure IAM password policy requires at least one symbol
        1.8 - Ensure IAM password policy requires at least one number
        1.9 - Ensure IAM password policy requires a minimum length of 14 or greater
        1.10 - Ensure IAM password policy prevents password reuse
        1.11 - Ensure IAM password policy expires passwords within 90 days or less
        """
        client = boto3.client('iam')

        # TODO: better exception handling
        try:
            client.update_account_password_policy(
                MinimumPasswordLength=14,  # 14 characters
                RequireSymbols=True,
                RequireNumbers=True,
                RequireUppercaseCharacters=True,
                RequireLowercaseCharacters=True,
                AllowUsersToChangePassword=True,
                MaxPasswordAge=90,  # days
                PasswordReusePrevention=24,  # last 24 passwords
                HardExpiry=False
            )
            self.logging.info("Updated IAM password policy with CIS AWS Foundations requirements.")
            return True
        except:
            self.logging.error(f"Could not update IAM password policy for {resource_id}.")
            self.logging.error(sys.exc_info()[1])
            return False
    
    def iam_user_unused_credentials_check(self, resource_id):
        """
        Deletes unused Access Keys and Login Profiles.
        """
        client = boto3.client('iam')
        
        response = client.list_users()
        
        for user in response.get('Users'):
            if resource_id == user.get('UserId'):
                user_name = user.get('UserName')
                
                # check password usage
                try:
                    login_profile = client.get_login_profile(UserName=user_name)
                    login_profile_date = login_profile.get('LoginProfile').get('CreateDate')
                except:
                    self.logging.error("Could not retrieve IAM Login Profile for User '%s'." % user_name)
                    self.logging.error(sys.exc_info()[1])
                    return False
                
                if SecurityHubRules.get_day_delta(login_profile_date) > 90:
                    try:
                        client.delete_login_profile(UserName=user_name)
                        self.logging.info("Deleted IAM Login Profile for User '%s'." % user_name)
                    except:
                        self.logging.error("Could not delete IAM Login Profile for User '%s'." % user_name)
                        self.logging.error(sys.exc_info()[1])
                        return False
                
                # check access keys usage
                try:
                    list_access_keys = client.list_access_keys(UserName=user_name)
                except:
                    self.logging.error("Could not list IAM Access Keys for User '%s'." % user_name)
                    self.logging.error(sys.exc_info()[1])
                    return False
                
                for access_key in list_access_keys.get('AccessKeyMetadata'):
                    access_key_id = access_key.get('AccessKeyId')
                    access_key_date = access_key.get('CreateDate')
                    access_key_status = access_key.get('Status')
                    
                    if access_key_status == 'Active':
                        if SecurityHubRules.get_day_delta(access_key_date) > 90:
                            try:
                                client.delete_access_key(AccessKeyId=access_key_id)
                                self.logging.info("Deleted IAM Access Key '%s' for User '%s'." % (access_key_id, user_name))
                            except:
                                self.logging.error("Could not delete IAM Access Key for User '%s'." % user_name)
                                self.logging.error(sys.exc_info()[1])
                                return False
                
                return True
    
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

            self.logging.info(f"Revoked public port 3389 ingress rule for Security Group '{resource_id}'.")
            return True
        except:
            self.logging.error(f"Could not revoke public port 3389 ingress rule for Security Group '{resource_id}'.")
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

            self.logging.info(f"Revoked public port 22 ingress rule for Security Group '{resource_id}'.")
            return True
        except:
            self.logging.error(f"Could not revoke public port 22 ingress rule for Security Group '{resource_id}'.")
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

            self.logging.info(f"ACL set to 'private' for S3 Bucket '{resource_id}'.")
            return True
        except:
            self.logging.info(f"Could not set ACL set to 'private' for S3 Bucket '{resource_id}'.")
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

            self.logging.info(f"ACL set to 'private' for S3 Bucket '{resource_id}'.")
            return True
        except:
            self.logging.info(f"Could not set ACL set to 'private' for S3 Bucket '{resource_id}'.")
            self.logging.error(sys.exc_info()[1])
            return False
    
    @staticmethod
    def convert_to_datetime(date):
        return dateutil.parser.isoparse(str(date)).replace(tzinfo=None)
    
    @staticmethod
    def get_day_delta(date):
        if date is not None:
            from_datetime = SecurityHubRules.convert_to_datetime(datetime.datetime.now().isoformat())
            to_datetime = SecurityHubRules.convert_to_datetime(date)
            delta = from_datetime - to_datetime
            
            return delta.days
        else:
            return 0