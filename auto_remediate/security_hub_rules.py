import datetime
import json
import sys

import boto3
import dateutil.parser


class SecurityHubRules:
    def __init__(self, logging):
        self.logging = logging

    def access_keys_rotated(self, resource_id):
        """Deletes IAM User's Access Keys over 90 days old.
        
        Arguments:
            resource_id {string} -- IAM Access Key ID
        
        Returns:
            boolean -- True if remediation is successful
        """
        client = boto3.client("iam")

        try:
            client.delete_access_key(AccessKeyId=resource_id)
            self.logging.info(f"Deleted unrotated IAM Access Key '{resource_id}'.")
            return True
        except:
            self.logging.error(
                f"Could not delete unrotated IAM Access Key '{resource_id}'."
            )
            self.logging.error(sys.exc_info()[1])
            return False

    def cloud_trail_cloud_watch_logs_enabled(self, resource_id):
        logs_client = boto3.client("logs")
        cloudtrail_client = boto3.client("cloudtrail")

        cloudwatch_log_group = f"CloudTrail/{resource_id}"

        # create CloudWatch Log Group
        try:
            logs_client.create_log_group(logGroupName=cloudwatch_log_group)
            self.logging.info(
                f"Created new CloudWatch Log Group '{cloudwatch_log_group}'."
            )
        except:
            self.logging.error(
                f"Could not create new CloudWatch Log Group '{cloudwatch_log_group}'."
            )
            self.logging.error(sys.exc_info()[1])
            return False
        else:
            try:
                response = logs_client.describe_log_groups(
                    logGroupNamePrefix=cloudwatch_log_group
                )
            except:
                self.logging.error(
                    f"Could not describe CloudWatch Log Group '{cloudwatch_log_group}'."
                )
                self.logging.error(sys.exc_info()[1])
                return False
            else:
                cloudwatch_log_group_arn = response.get("logGroups")[0].get("arn")
                self.logging.info(
                    f"Retrieved ARN '{cloudwatch_log_group_arn}' for CloudWatch Log Group '{cloudwatch_log_group}'."
                )

        # update CloudTrail
        try:
            cloudtrail_client.update_trail(
                Name=resource_id, CloudWatchLogsLogGroupArn=cloudwatch_log_group_arn
            )
            self.logging.info(
                f"Added CloudWatch Log Group '{cloudwatch_log_group}' to CloudTrail '{resource_id}'."
            )
        except:
            self.logging.error(f"Could not update CloudTrail '{resource_id}'.")
            self.logging.error(sys.exc_info()[1])
            return False

    def cloud_trail_encryption_enabled(self, resource_id):
        """Encrypts CloudTrail logs by creating a new KMS Key
        
        Arguments:
            resource_id {string} -- CloudTrail name
        
        Returns:
            boolean -- True if remediation was successful
        """
        cloudtrail_client = boto3.client("cloudtrail")
        kms_client = boto3.client("kms")
        sts_client = boto3.client("sts")

        # get account number and ARN
        try:
            account_number = sts_client.get_caller_identity().get("Account")
            account_arn = sts_client.get_caller_identity().get("Arn")
        except:
            self.logging.error("Could not get Account Number and ARN.")
            self.logging.error(sys.exc_info()[1])
            return False

        # TODO Check if KMS Alias already exists, if it does then re-use

        # get KMS policy
        try:
            file_path = (
                "auto_remediate/data/cloud_trail_encryption_enabled_kms_policy.json"
            )
            with open(file_path) as file:
                kms_policy = str(file.read())
        except:
            self.logging.error(f"Could not read file '{file_path}'.")
            self.logging.error(sys.exc_info()[1])
            return False
        else:
            kms_policy = kms_policy.replace("account_number", account_number)
            kms_policy = kms_policy.replace("account_arn", account_arn)

        # create KMS CMK
        try:
            response = kms_client.create_key(
                Policy=kms_policy, Description=f"Key for CloudTrail {resource_id}"
            )
        except:
            self.logging.error(
                f"Could not create new KMS Customer Managed Key for CloudTrail '{resource_id}'."
            )
            self.logging.error(sys.exc_info()[1])
            return False
        else:
            kms_key_id = response.get("KeyMetadata").get("KeyId")
            self.logging.info(
                f"Created new KMS Customer Managed Key '{kms_key_id}' for CloudTrail '{resource_id}'."
            )

        # create alias
        try:
            kms_client.create_alias(
                AliasName=f"alias/cloudtrail/{resource_id}", TargetKeyId=kms_key_id
            )
            self.logging.info(
                f"Created new KMS Alias 'cloudtrail/{resource_id}' for KMS Key '{kms_key_id}'."
            )
        except:
            self.logging.error(
                f"Could not create KMS Alias 'cloudtrail/{resource_id}' for KMS Key '{kms_key_id}'."
            )
            self.logging.error(sys.exc_info()[1])

            try:
                kms_client.schedule_key_deletion(
                    KeyId=kms_key_id, PendingWindowInDays=7
                )
                self.logging.info(f"Scheduled KMS CMK '{kms_key_id}' for deletion.")
            except:
                self.logging.error(f"Could not delete KMS CMK '{kms_key_id}'.")

            return False

        # update CloudTrail
        try:
            cloudtrail_client.update_trail(Name=resource_id, KmsKeyId=kms_key_id)
            self.logging.info(
                f"Encrypted CloudTrail '{resource_id}' with new KMS Customer Managed Key '{kms_key_id}'."
            )
            return True
        except:
            self.logging.error(
                f"Could not encrypt CloudTrail '{resource_id}' with new KMS Customer Managed Key '{kms_key_id}'."
            )
            self.logging.error(sys.exc_info()[1])

            try:
                kms_client.schedule_key_deletion(
                    KeyId=kms_key_id, PendingWindowInDays=7
                )
                self.logging.info(f"Scheduled KMS CMK '{kms_key_id}' for deletion.")
            except:
                self.logging.error(f"Could not delete KMS CMK '{kms_key_id}'.")

            return False

    def cmk_backing_key_rotation_enabled(self, resource_id):
        """Enables key rotation for KMS Customer Managed Keys.
        
        Arguments:
            resource_id {string} -- KMS Key ID
        
        Returns:
            boolean -- True if remediation was successful
        """
        client = boto3.client("kms")

        try:
            client.enable_key_rotation(KeyId=resource_id)
            self.logging.info(
                f"Enabled key rotation for Customer Managed Key '{resource_id}'."
            )
            return True
        except:
            self.logging.error(
                f"Could not enable key rotation for Customer Managed Key '{resource_id}'."
            )
            self.logging.error(sys.exc_info()[1])
            return False

    def iam_password_policy(self, resource_id):
        """Applies a sensible IAM password policy, as per CIS AWS Foundations Standard Checks Supported in Security Hub
        1.5 - Ensure IAM password policy requires at least one uppercase letter
        1.6 - Ensure IAM password policy requires at least one lowercase letter
        1.7 - Ensure IAM password policy requires at least one symbol
        1.8 - Ensure IAM password policy requires at least one number
        1.9 - Ensure IAM password policy requires a minimum length of 14 or greater
        1.10 - Ensure IAM password policy prevents password reuse
        1.11 - Ensure IAM password policy expires passwords within 90 days or less
        
        Arguments:
            resource_id {string} -- AWS Account ID
        
        Returns:
            boolean -- True if remediation was succesfull
        """
        client = boto3.client("iam")

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
                HardExpiry=False,
            )
            self.logging.info(
                f"Updated IAM password policy with CIS AWS Foundations "
                f"requirements for Account '{resource_id}'."
            )
            return True
        except:
            self.logging.error(
                f"Could not update IAM password policy for Account '{resource_id}'."
            )
            self.logging.error(sys.exc_info()[1])
            return False

    def iam_policy_no_statements_with_admin_access(self, resource_id):
        """Removes IAM Polciy Statements that have
        "Effect": "Allow" with "Action": "*" over "Resource": "*".
        
        Arguments:
            resource_id {string} -- IAM Policy ID
        
        Returns:
            boolean -- True if remediation was successful
        """
        client = boto3.client("iam")

        try:
            paginator = client.get_paginator("list_policies").paginate()
        except:
            self.logging.error("Could not get a paginator to list all IAM Policies.")
            self.logging.error(sys.exc_info()[1])
            return False

        for policy_arn in paginator.search(
            f"Policies[?PolicyId == '{resource_id}'].Arn"
        ):
            # get policy
            try:
                response = client.get_policy(PolicyArn=policy_arn)
            except:
                self.logging.error(f"Could not get IAM Policy '{policy_arn}' details.")
                self.logging.error(sys.exc_info()[1])
                return False

            default_version = response.get("Policy").get("DefaultVersionId")

            # get default policy
            try:
                response = client.get_policy_version(
                    PolicyArn=policy_arn, VersionId=default_version
                )
            except:
                self.logging.error(
                    f"Could not get Policy Version for IAM Policy '{policy_arn}'."
                )
                self.logging.error(sys.exc_info()[1])
                return False

            # remove admin statements from policy
            policy = response.get("PolicyVersion").get("Document")
            for statement in policy.get("Statement"):
                if (
                    statement.get("Action") == "*"
                    and statement.get("Effect") == "Allow"
                    and statement.get("Resource") == "*"
                ):
                    policy.get("Statement").remove(statement)
                    self.logging.info(
                        f"Removed Statement '{statement}' from IAM Policy '{policy_arn}'."
                    )

            # create new policy version with offending statement removed
            try:
                client.create_policy_version(
                    PolicyArn=policy_arn,
                    PolicyDocument=json.dumps(policy),
                    SetAsDefault=True,
                )
                self.logging.info(
                    f"Created new Policy Version '{policy}' for IAM Policy '{policy_arn}'."
                )
            except:
                self.logging.error(
                    f"Could not create a new Policy Version '{policy}' for IAM Policy '{policy_arn}'."
                )
                self.logging.error(sys.exc_info()[1])
                return False
        return True

    def iam_user_unused_credentials_check(self, resource_id):
        """Deletes unused Access Keys and Login Profiles over 90 days old for a given IAM User.
        
        Arguments:
            resource_id {string} -- IAM User ID
        
        Returns:
            boolean -- True if remediation was successful
        """
        client = boto3.client("iam")

        try:
            paginator = client.get_paginator("list_users").paginate()
        except:
            self.logging.error("Could not get a paginator to list all IAM users.")
            self.logging.error(sys.exc_info()[1])
            return False

        for user_name in paginator.search(
            f"Users[?UserId == '{resource_id}'].UserName"
        ):
            # check password usage
            try:
                login_profile = client.get_login_profile(UserName=user_name)
            except client.exceptions.NoSuchEntityException:
                self.logging.debug(
                    f"IAM User '{user_name}' does not have a Login Profile to delete."
                )
            except:
                self.logging.error(
                    f"Could not retrieve IAM Login Profile for User '{user_name}'."
                )
                self.logging.error(sys.exc_info()[1])
            else:
                login_profile_date = login_profile.get("LoginProfile").get("CreateDate")
                if SecurityHubRules.get_day_delta(login_profile_date) > 90:
                    try:
                        client.delete_login_profile(UserName=user_name)
                        self.logging.info(
                            f"Deleted IAM Login Profile for User '{user_name}'."
                        )
                    except:
                        self.logging.error(
                            f"Could not delete IAM Login Profile for User '{user_name}'."
                        )
                        self.logging.error(sys.exc_info()[1])
                        return False

            # check access keys usage
            try:
                list_access_keys = client.list_access_keys(UserName=user_name)
            except:
                self.logging.error(
                    f"Could not list IAM Access Keys for User '{user_name}'."
                )
                self.logging.error(sys.exc_info()[1])
                return False

            for access_key in list_access_keys.get("AccessKeyMetadata"):
                access_key_id = access_key.get("AccessKeyId")
                access_key_date = access_key.get("CreateDate")
                access_key_status = access_key.get("Status")

                if (
                    access_key_status == "Active"
                    and SecurityHubRules.get_day_delta(access_key_date) > 90
                ):
                    try:
                        client.delete_access_key(
                            UserName=user_name, AccessKeyId=access_key_id
                        )
                        self.logging.info(
                            f"Deleted IAM Access Key '{access_key_id}' for User '{user_name}'."
                        )
                    except:
                        self.logging.error(
                            f"Could not delete IAM Access Key for User '{user_name}'."
                        )
                        self.logging.error(sys.exc_info()[1])
                        return False

            return True

    def restricted_rdp(self, resource_id):
        """Deletes inbound rules within Security Groups that match:
            Protocol: TCP
            Port: 3389
            Source: 0.0.0.0/0 or ::/0
        
        Arguments:
            resource_id {string} -- EC2 Security Group ID
        
        Returns:
            boolean -- True if remediation was successful
        """
        client = boto3.client("ec2")

        try:
            client.revoke_security_group_ingress(
                GroupId=resource_id,
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

            self.logging.info(
                f"Revoked public port 3389 ingress rule for Security Group '{resource_id}'."
            )
            return True
        except:
            self.logging.error(
                f"Could not revoke public port 3389 ingress rule for Security Group '{resource_id}'."
            )
            self.logging.error(sys.exc_info()[1])
            return False

    def restricted_ssh(self, resource_id):
        """Deletes inbound rules within Security Groups that match:
            Protocol: TCP
            Port: 22
            Source: 0.0.0.0/0 or ::/0
        
        Arguments:
            resource_id {string} -- EC2 Security Group ID
        
        Returns:
            boolean -- True if remediation was successful
        """
        client = boto3.client("ec2")

        try:
            client.revoke_security_group_ingress(
                GroupId=resource_id,
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

            self.logging.info(
                f"Revoked public port 22 ingress rule for Security Group '{resource_id}'."
            )
            return True
        except:
            self.logging.error(
                f"Could not revoke public port 22 ingress rule for Security Group '{resource_id}'."
            )
            self.logging.error(sys.exc_info()[1])
            return False

    def s3_bucket_public_read_prohibited(self, resource_id):
        """Sets the S3 Bucket ACL to "private" to prevent the Bucket from being publicly read.
        
        Arguments:
            resource_id {string} -- S3 Bucket Name
        
        Returns:
            boolean -- True if remediation was successful
        """
        client = boto3.client("s3")

        try:
            client.put_bucket_acl(ACL="private", Bucket=resource_id)

            self.logging.info(f"ACL set to 'private' for S3 Bucket '{resource_id}'.")
            return True
        except:
            self.logging.error(
                f"Could not set ACL set to 'private' for S3 Bucket '{resource_id}'."
            )
            self.logging.error(sys.exc_info()[1])
            return False

    def s3_bucket_public_write_prohibited(self, resource_id):
        """Sets the S3 Bucket ACL to "private" to prevent the Bucket from being publicly written to.
        
        Arguments:
            resource_id {string} -- S3 Bucket Name
        
        Returns:
            boolean -- True if remediation was successful
        """
        client = boto3.client("s3")

        try:
            client.put_bucket_acl(ACL="private", Bucket=resource_id)

            self.logging.info(f"ACL set to 'private' for S3 Bucket '{resource_id}'.")
            return True
        except:
            self.logging.error(
                f"Could not set ACL set to 'private' for S3 Bucket '{resource_id}'."
            )
            self.logging.error(sys.exc_info()[1])
            return False

    def s3_bucket_logging_enabled(self, resource_id):
        """Enables server access logging for an S3 Bucket by creating a new S3 Bucket
        with the name "<resource_id>-access-logs".
        
        Arguments:
            resource_id {string} -- S3 Bucket Name
        
        Returns:
            boolean -- True if remediation was successful
        """
        client = boto3.client("s3")
        log_bucket = f"{resource_id}-access-logs"

        # create new Bucket for logs
        try:
            client.create_bucket(
                ACL="log-delivery-write",  # see https://docs.aws.amazon.com/AmazonS3/latest/dev/acl-overview.html#canned-acl
                Bucket=log_bucket,
                CreateBucketConfiguration={
                    "LocationConstraint": client.meta.region_name
                },
            )

            self.logging.info(
                f"Created new S3 Bucket '{log_bucket}' "
                f"for storing server access logs for S3 Bucket '{resource_id}'."
            )
        except:
            self.logging.error(
                f"Could not create new S3 Bucket '{log_bucket}' "
                f"for storing server access logs for S3 Bucket '{resource_id}'."
            )
            self.logging.error(sys.exc_info()[1])
            return False

        # add log Bucket logging (into itself)
        try:
            client.put_bucket_logging(
                Bucket=log_bucket,
                BucketLoggingStatus={
                    "LoggingEnabled": {
                        "TargetBucket": log_bucket,
                        "TargetPrefix": "self/",
                    }
                },
            )

            self.logging.info(
                f"Server access logging enabled for "
                f"S3 Bucket '{log_bucket}' to S3 Bucket '{log_bucket}'."
            )
        except:
            self.logging.error(
                f"Could not enable server access logging enabled for "
                f"S3 Bucket '{log_bucket}' to S3 Bucket '{log_bucket}'."
            )
            self.logging.error(sys.exc_info()[1])

            try:
                client.delete_bucket(Bucket=log_bucket)
                self.logging.info(f"Deleted S3 Bucket '{log_bucket}'.")
            except:
                self.logging.error(f"Could not delete S3 Bucket '{log_bucket}'.")

            return False

        # add original Bucket logging into the log Bucket
        try:
            client.put_bucket_logging(
                Bucket=resource_id,
                BucketLoggingStatus={
                    "LoggingEnabled": {"TargetBucket": log_bucket, "TargetPrefix": ""}
                },
            )

            self.logging.info(
                f"Server access logging enabled for "
                f"S3 Bucket '{resource_id}' to S3 Bucket '{log_bucket}'."
            )
            return True
        except:
            self.logging.error(
                f"Could not enable server access logging enabled for "
                f"S3 Bucket '{resource_id}' to S3 Bucket '{log_bucket}'."
            )
            self.logging.error(sys.exc_info()[1])

            try:
                client.delete_bucket(Bucket=log_bucket)
                self.logging.info(f"Deleted S3 Bucket '{log_bucket}'.")
            except:
                self.logging.error(f"Could not delete S3 Bucket '{log_bucket}'.")

            return False

    def vpc_default_security_group_closed(self, resource_id):
        """Removes all egress and ingress rules for a Security Group
        
        Arguments:
            resource_id {string} -- Security Group ID
        
        Returns:
            boolean -- True if remediation was successful
        """
        client = boto3.client("ec2")

        try:
            response = client.describe_security_groups(GroupIds=[resource_id])
        except:
            self.logging.error(
                f"Could not describe default Security Group '{resource_id}'."
            )
            self.logging.error(sys.exc_info()[1])
            return False

        for security_group in response.get("SecurityGroups"):
            # revoke egress rule
            try:
                client.revoke_security_group_egress(
                    GroupId=resource_id,
                    IpPermissions=security_group.get("IpPermissionsEgress"),
                )
                self.logging.info(
                    f"Revoked all egress rules for default Security Group '{resource_id}'."
                )
                return True
            except:
                self.logging.error(
                    f"Could not revoke egress rules for default Security Group '{resource_id}'."
                )
                self.logging.error(sys.exc_info()[1])
                return False

            # revoke ingress rules
            try:
                client.revoke_security_group_ingress(
                    GroupId=resource_id,
                    IpPermissions=security_group.get("IpPermissions"),
                )
                self.logging.info(
                    f"Revoked all ingress rules for default Security Group '{resource_id}'."
                )
                return True
            except:
                self.logging.error(
                    f"Could not revoke ingress rules for default Security Group '{resource_id}'."
                )
                self.logging.error(sys.exc_info()[1])
                return False

    def vpc_flow_logs_enabled(self, resource_id):
        """Enables VPC Flow Logs by creating a new S3 Bucket with the name "<resource_id>-flow-logs".
        
        Arguments:
            resource_id {string} -- VPC ID
        
        Returns:
            boolean -- True if remediation was successful
        """
        s3_client = boto3.client("s3")
        ec2_client = boto3.client("ec2")
        log_bucket = f"{resource_id}-flow-logs"

        # create new Bucket for logs
        try:
            s3_client.create_bucket(
                ACL="log-delivery-write",
                Bucket=log_bucket,
                CreateBucketConfiguration={
                    "LocationConstraint": s3_client.meta.region_name
                },
            )

            self.logging.info(
                f"Created new S3 Bucket '{log_bucket}' "
                f"for storing server access logs for S3 Bucket '{resource_id}'."
            )
        except:
            self.logging.error(
                f"Could not create new S3 Bucket '{log_bucket}' "
                f"for storing server access logs for S3 Bucket '{resource_id}'."
            )
            self.logging.error(sys.exc_info()[1])
            return False

        # add log Bucket logging (into itself)
        try:
            s3_client.put_bucket_logging(
                Bucket=log_bucket,
                BucketLoggingStatus={
                    "LoggingEnabled": {
                        "TargetBucket": log_bucket,
                        "TargetPrefix": "self/",
                    }
                },
            )

            self.logging.info(
                f"Server access logging enabled for "
                f"S3 Bucket '{log_bucket}' to S3 Bucket '{log_bucket}'."
            )
        except:
            self.logging.error(
                f"Could not enable server access logging enabled for "
                f"S3 Bucket '{log_bucket}' to S3 Bucket '{log_bucket}'."
            )
            self.logging.error(sys.exc_info()[1])

            try:
                s3_client.delete_bucket(Bucket=log_bucket)
                self.logging.info(f"Deleted S3 Bucket '{log_bucket}'.")
            except:
                self.logging.error(f"Could not delete S3 Bucket '{log_bucket}'.")

            return False

        # add VPC flow logs
        try:
            ec2_client.create_flow_logs(
                ResourceIds=[resource_id],
                ResourceType="VPC",
                TrafficType="REJECT",
                LogDestinationType="s3",
                LogDestination=f"arn:aws:s3:::{log_bucket}",
            )

            self.logging.info(
                f"VPC Flow Logs have been enabled for "
                f"VPC '{resource_id}' to S3 Bucket '{log_bucket}'."
            )
            return True
        except:
            self.logging.error(
                f"Could not enable VPC Flow Logs for "
                f"VPC '{resource_id}' to S3 Bucket '{log_bucket}'."
            )
            self.logging.error(sys.exc_info()[1])

            try:
                s3_client.delete_bucket(Bucket=log_bucket)
                self.logging.info(f"Deleted S3 Bucket '{log_bucket}'.")
            except:
                self.logging.error(f"Could not delete S3 Bucket '{log_bucket}'.")

            return False

    @staticmethod
    def convert_to_datetime(date):
        """Converts Boto3 returns timestamp strings to datetime objects
        
        Arguments:
            date {string} -- Boto3 timestamp
        
        Returns:
            datetime -- datetime timestamp
        """
        return dateutil.parser.isoparse(str(date)).replace(tzinfo=None)

    @staticmethod
    def get_day_delta(date):
        """Returns the delta between the given date and now in days.
        
        Arguments:
            date {string} -- Boto3 timestamp
        
        Returns:
            integer -- Number of days between input date and now
        """
        if date is not None:
            from_datetime = SecurityHubRules.convert_to_datetime(
                datetime.datetime.now().isoformat()
            )
            to_datetime = SecurityHubRules.convert_to_datetime(date)
            delta = from_datetime - to_datetime

            return delta.days
        else:
            return 0
