import datetime
import json
import sys
import time

import boto3
import dateutil.parser


class SecurityHubRules:
    def __init__(self, logging):
        self.logging = logging

        self._client_cloudtrail = None
        self._client_ec2 = None
        self._client_iam = None
        self._client_kms = None
        self._client_logs = None
        self._client_s3 = None
        self._client_sts = None
        
        self._account_number = None
        self._account_arn = None
        self._region = None

    @property
    def client_cloudtrail(self):
        if not self._client_cloudtrail:
            self._client_cloudtrail = boto3.client("cloudtrail")
        return self._client_cloudtrail

    @client_cloudtrail.setter
    def client_cloudtrail(self, client):
        self._client_cloudtrail = client

    @property
    def client_ec2(self):
        if not self._client_ec2:
            self._client_ec2 = boto3.client("ec2")
        return self._client_ec2

    @client_ec2.setter
    def client_ec2(self, client):
        self._client_ec2 = client

    @property
    def client_iam(self):
        if not self._client_iam:
            self._client_iam = boto3.client("iam")
        return self._client_iam

    @client_iam.setter
    def client_iam(self, client):
        self._client_iam = client

    @property
    def client_logs(self):
        if not self._client_kms:
            self._client_logs = boto3.client("logs")
        return self._client_logs

    @client_logs.setter
    def client_logs(self, client):
        self._client_logs = client

    @property
    def client_kms(self):
        if not self._client_kms:
            self._client_kms = boto3.client("kms")
        return self._client_kms

    @client_kms.setter
    def client_kms(self, client):
        self._client_kms = client

    @property
    def client_s3(self):
        if not self._client_s3:
            self._client_s3 = boto3.client("s3")
        return self._client_s3

    @client_s3.setter
    def client_s3(self, client):
        self._client_s3 = client

    @property
    def client_sts(self):
        if not self._client_sts:
            self._client_sts = boto3.client("sts")
        return self._client_sts

    @client_sts.setter
    def client_sts(self, client):
        self._client_sts = client
    
    @property
    def account_number(self):
        if not self._account_number:
            self._account_number = self.client_sts.get_caller_identity().get("Account")
        return self._account_number

    @account_number.setter
    def account_number(self, account_number):
        self._account_number = account_number
    
    @property
    def account_arn(self):
        if not self._account_arn:
            self._account_arn = self.client_sts.get_caller_identity().get("Arn")
        return self._account_arn

    @account_arn.setter
    def account_arn(self, account_arn):
        self._account_arn = account_arn
    
    @property
    def region(self):
        if not self._region:
            self._region = self.client_sts.meta.region_name
        return self._region

    @region.setter
    def region(self, region):
        self._region = region

    def access_keys_rotated(self, resource_id):
        """Deletes IAM User's Access Keys over 90 days old.
        
        Arguments:
            resource_id {string} -- IAM Access Key ID
        
        Returns:
            boolean -- True if remediation is successful
        """
        try:
            self.client_iam.delete_access_key(AccessKeyId=resource_id)
            self.logging.info(f"Deleted unrotated IAM Access Key '{resource_id}'.")
            return True
        except:
            self.logging.error(
                f"Could not delete unrotated IAM Access Key '{resource_id}'."
            )
            self.logging.error(sys.exc_info()[1])
            return False

    def cloud_trail_cloud_watch_logs_enabled(self, resource_id):
        """Adds CloudWatch Log Group to CloudTrail logs
        
        Arguments:
            resource_id {string} -- CloudTrail name
        
        Returns:
            boolean -- True if remediation was successful
        """
        cloudwatch_log_group_name = f"/aws/cloudtrail/{resource_id}"

        # create CloudWatch Log Group
        try:
            self.client_logs.create_log_group(logGroupName=cloudwatch_log_group_name)
            self.logging.info(
                f"Created new CloudWatch Log Group '{cloudwatch_log_group_name}'."
            )
        except:
            self.logging.error(
                f"Could not create new CloudWatch Log Group '{cloudwatch_log_group_name}'."
            )
            self.logging.error(sys.exc_info()[1])
            return False
        else:
            try:
                response = self.client_logs.describe_log_groups(
                    logGroupNamePrefix=cloudwatch_log_group_name
                )
            except:
                self.logging.error(
                    f"Could not describe CloudWatch Log Group '{cloudwatch_log_group_name}'."
                )
                self.logging.error(sys.exc_info()[1])
                self.delete_log_group(cloudwatch_log_group_name)
                return False
            else:
                cloudwatch_log_group_arn = response.get("logGroups")[0].get("arn")
                self.logging.info(
                    f"Retrieved ARN '{cloudwatch_log_group_arn}' for CloudWatch Log Group '{cloudwatch_log_group_name}'."
                )

        # get trust relationship
        trust_relationship_file = "auto_remediate/data/cloud_trail_cloud_watch_logs_enabled_trust_relationship.json"
        with open(trust_relationship_file, "r") as file:
            trust_relationship = file.read()

        # create IAM Role for CloudTrail
        iam_role_name = f"CloudTrail-CloudWatchLogs-{resource_id}"
        try:
            response = self.client_iam.create_role(
                RoleName=iam_role_name,
                AssumeRolePolicyDocument=trust_relationship,
                Description="AWS CloudTrail will assume the role to deliver CloudTrail events to the CloudWatch Logs log group",
            )
            self.logging.info(f"Created new IAM Role '{iam_role_name}'.")
        except:
            self.logging.error(f"Could not create new IAM Role '{iam_role_name}'.")
            self.logging.error(sys.exc_info()[1])
            self.delete_log_group(cloudwatch_log_group_name)
            return False
        else:
            iam_role_arn = response.get("Role").get("Arn")
            iam_policy_name = f"CloudTrail-CloudWatch-{resource_id}"

            # create policy
            policy_file = (
                "auto_remediate/data/cloud_trail_cloud_watch_logs_enabled_policy.json"
            )
            with open(policy_file, "r") as file:
                policy = file.read()

            policy = policy.replace("_ACCOUNT_NUMBER_", self.account_number)
            policy = policy.replace("_REGION_", self.region)
            policy = policy.replace("_LOG_GROUP_", cloudwatch_log_group_name)

            try:
                self.client_iam.put_role_policy(
                    RoleName=iam_role_name,
                    PolicyName=iam_policy_name,
                    PolicyDocument=policy,
                )

                self.logging.info(
                    f"Added IAM Policy '{iam_policy_name}' to IAM Role '{iam_role_name}'."
                )
            except:
                self.logging.error(
                    f"Could not add IAM Policy '{iam_policy_name}' to IAM Role '{iam_role_name}'."
                )
                self.logging.error(sys.exc_info()[1])
                self.delete_role(iam_role_name)
                self.delete_log_group(cloudwatch_log_group_name)
                return False

        # update CloudTrail with CloudWatch Log Group with a backoff
        # to allow AWS the time to create the IAM Role
        try:
            waiter = self.client_iam.get_waiter("role_exists")
            waiter.wait(RoleName=iam_role_name, WaiterConfig={"Delay": 2})
        except:
            self.logging.error(sys.exc_info()[1])
            self.delete_role_policy(iam_role_name, iam_policy_name)
            self.delete_role(iam_role_name)
            self.delete_log_group(cloudwatch_log_group_name)
            return False

        try:
            self.client_cloudtrail.update_trail(
                Name=resource_id,
                CloudWatchLogsLogGroupArn=cloudwatch_log_group_arn,
                CloudWatchLogsRoleArn=iam_role_arn,
            )
            self.logging.info(
                f"Added CloudWatch Log Group '{cloudwatch_log_group_name}' to CloudTrail '{resource_id}'."
            )
            return True
        except:
            self.logging.error(f"Could not update CloudTrail '{resource_id}'.")
            self.logging.error(sys.exc_info()[1])
            self.delete_role_policy(iam_role_name, iam_policy_name)
            self.delete_role(iam_role_name)
            self.delete_log_group(cloudwatch_log_group_name)
            return False

    def cloud_trail_encryption_enabled(self, resource_id):
        """Encrypts CloudTrail logs with a KMS Customer Managed Key.
        
        Arguments:
            resource_id {string} -- CloudTrail name
        
        Returns:
            boolean -- True if remediation was successful
        """
        # create KMS Policy
        kms_policy_file = (
            "auto_remediate/data/cloud_trail_encryption_enabled_kms_policy.json"
        )
        with open(kms_policy_file, "r") as file:
            kms_policy = file.read()

        kms_policy = kms_policy.replace("_ACCOUNT_NUMBER_", self.account_number)
        kms_policy = kms_policy.replace("_ACCOUNT_ARN_", self.account_arn)

        # create KMS Customer Managed Key
        try:
            response = self.client_kms.create_key(
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

        # create KMS Alias
        kms_alias_name = f"alias/cloudtrail/{resource_id}"
        try:
            self.client_kms.create_alias(
                AliasName=kms_alias_name, TargetKeyId=kms_key_id
            )
            self.logging.info(
                f"Created new KMS Alias '{kms_alias_name}' for KMS Key '{kms_key_id}'."
            )
        except self.client_kms.exceptions.AlreadyExistsException:
            self.logging.info(f"KMS Alias '{kms_alias_name}' already exists.")
        except:
            self.logging.error(
                f"Could not create KMS Alias '{kms_alias_name}' for KMS Key '{kms_key_id}'."
            )
            self.logging.error(sys.exc_info()[1])
            self.schedule_key_deletion(kms_key_id)
            return False

        # update CloudTrail with KMS Customer Managed Key
        try:
            self.client_cloudtrail.update_trail(Name=resource_id, KmsKeyId=kms_key_id)
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
                self.client_kms.delete_alias(AliasName=kms_alias_name)
                self.logging.info(f"Deleted KMS Alias '{kms_alias_name}'.")
            except:
                self.logging.error(f"Could not delete KMS Alias '{kms_alias_name}'.")
                self.logging.error(sys.exc_info()[1])
            self.schedule_key_deletion(kms_key_id)
            return False

    def cloud_trail_log_file_validation_enabled(self, resource_id):
        """Enables CloudTrail file validation
        
        Arguments:
            resource_id {string} -- CloudTrail Name
        
        Returns:
            boolean -- True if remediation is successful
        """
        try:
            self.client_cloudtrail.update_trail(
                Name=resource_id, EnableLogFileValidation=True
            )
            self.logging.info(
                f"Enabled Log File Validation for CloudTrail '{resource_id}'."
            )
            return True
        except:
            self.logging.error(
                f"Could not enable Log File Validation for CloudTrail '{resource_id}'."
            )
            self.logging.error(sys.exc_info()[1])
            return False

    def cmk_backing_key_rotation_enabled(self, resource_id):
        """Enables key rotation for KMS Customer Managed Keys.
        
        Arguments:
            resource_id {string} -- KMS Key ID
        
        Returns:
            boolean -- True if remediation was successful
        """
        try:
            self.client_kms.enable_key_rotation(KeyId=resource_id)
            self.logging.info(
                f"Enabled key rotation for KMS Customer Managed Key '{resource_id}'."
            )
            return True
        except self.client_kms.exceptions.KMSInvalidStateException:
            self.logging.warning(
                f"Could not enable key rotation for KMS Customer Managed Key '{resource_id}' due to invalid state."
            )
            self.logging.warning(sys.exc_info()[1])
            return False
        except:
            self.logging.error(
                f"Could not enable key rotation for KMS Customer Managed Key '{resource_id}'."
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
        try:
            self.client_iam.update_account_password_policy(
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
        try:
            paginator = self.client_iam.get_paginator("list_policies").paginate()
        except:
            self.logging.error("Could not get a paginator to list all IAM Policies.")
            self.logging.error(sys.exc_info()[1])
            return False

        for policy_arn in paginator.search(
            f"Policies[?PolicyId == '{resource_id}'].Arn"
        ):
            # get policy
            try:
                response = self.client_iam.get_policy(PolicyArn=policy_arn)
            except:
                self.logging.error(f"Could not get IAM Policy '{policy_arn}' details.")
                self.logging.error(sys.exc_info()[1])
                return False

            default_version = response.get("Policy").get("DefaultVersionId")

            # get default policy
            try:
                response = self.client_iam.get_policy_version(
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
                self.client_iam.create_policy_version(
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

    def iam_user_no_policies_check(self, resource_id):
        """ Detaches user policies from IAM user

        Arguments:
            resource_id {string} -- IAM User ID

        Returns:
            boolean -- True if remediation was successful
        """
        try:
            page_user = self.client_iam.get_paginator("list_users").paginate()
            for username in page_user.search(
                f"Users[?UserId == '{resource_id}'].UserName"
            ):
                page_policy = self.client_iam.get_paginator(
                    "list_attached_user_policies"
                ).paginate(UserName=username)
                for policy_arn in page_policy.search(f"AttachedPolicies[].PolicyArn"):
                    self.client_iam.detach_user_policy(
                        UserName=username, PolicyArn=policy_arn
                    )
                    self.logging.info(
                        f"Detached '{policy_arn}' from '{username}' '{resource_id}'."
                    )
                    return True
        except:
            self.logging.error(f"Could not detach user policies for '{resource_id}'.")
            self.logging.error(sys.exc_info()[1])
            return False

    def iam_user_unused_credentials_check(self, resource_id):
        """Deletes unused Access Keys and Login Profiles over 90 days old for a given IAM User.
        
        Arguments:
            resource_id {string} -- IAM User ID
        
        Returns:
            boolean -- True if remediation was successful
        """
        try:
            paginator = self.client_iam.get_paginator("list_users").paginate()
        except:
            self.logging.error("Could not get a paginator to list all IAM users.")
            self.logging.error(sys.exc_info()[1])
            return False

        for user_name in paginator.search(
            f"Users[?UserId == '{resource_id}'].UserName"
        ):
            # check password usage
            try:
                login_profile = self.client_iam.get_login_profile(UserName=user_name)
            except self.client_iam.exceptions.NoSuchEntityException:
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
                        self.client_iam.delete_login_profile(UserName=user_name)
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
                list_access_keys = self.client_iam.list_access_keys(UserName=user_name)
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
                        self.client_iam.delete_access_key(
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

    def multi_region_cloud_trail_enabled(self, resource_id):
        """Enables multi region CloudTrail
        
        Arguments:
            resource_id {string} -- CloudTrail Name
        
        Returns:
            boolean -- True if remediation is successful
        """
        try:
            self.client_cloudtrail.update_trail(
                Name=resource_id, IsMultiRegionTrail=True
            )
            self.logging.info(
                f"Enabled multi region trail for CloudTrail '{resource_id}'."
            )
            return True
        except:
            self.logging.error(
                f"Could not enable multi region trail for CloudTrail '{resource_id}'."
            )
            self.logging.error(sys.exc_info()[1])
            return False

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

        try:
            self.client_ec2.revoke_security_group_ingress(
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
        try:
            self.client_ec2.revoke_security_group_ingress(
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
        try:
            self.client_s3.put_bucket_acl(ACL="private", Bucket=resource_id)

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
        try:
            self.client_s3.put_bucket_acl(ACL="private", Bucket=resource_id)

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
        log_bucket = f"{self.account_number}-{self.region}-access-logs"

        # create new Bucket for logs
        try:
            self.client_s3.create_bucket(
                ACL="log-delivery-write",  # see https://docs.aws.amazon.com/AmazonS3/latest/dev/acl-overview.html#canned-acl
                Bucket=log_bucket,
                CreateBucketConfiguration={"LocationConstraint": self.region},
            )

            self.logging.info(
                f"Created new S3 Bucket '{log_bucket}' "
                f"for storing server access logs for S3 Bucket '{resource_id}'."
            )
        except self.client_s3.exceptions.BucketAlreadyOwnedByYou:
            self.logging.info(
                f"Skipped creation of S3 Bucket '{log_bucket}' as it already exists."
            )
        except:
            self.logging.error(
                f"Could not create new S3 Bucket '{log_bucket}' "
                f"for storing server access logs for S3 Bucket '{resource_id}'."
            )
            self.logging.error(sys.exc_info()[1])
            return False

        # add original Bucket logging into the log Bucket
        try:
            self.client_s3.put_bucket_logging(
                Bucket=resource_id,
                BucketLoggingStatus={
                    "LoggingEnabled": {
                        "TargetBucket": log_bucket,
                        "TargetPrefix": f"{resource_id}/",
                    }
                },
            )

            self.logging.info(
                f"Server access logging enabled for "
                f"S3 Bucket '{resource_id}' to S3 Bucket '{log_bucket}/{resource_id}'."
            )
            return True
        except:
            self.logging.error(
                f"Could not enable server access logging enabled for "
                f"S3 Bucket '{resource_id}' to S3 Bucket '{log_bucket}/{resource_id}'."
            )
            self.logging.error(sys.exc_info()[1])
            return False

    def vpc_default_security_group_closed(self, resource_id):
        """Removes all egress and ingress rules for a Security Group
        
        Arguments:
            resource_id {string} -- Security Group ID
        
        Returns:
            boolean -- True if remediation was successful
        """
        try:
            response = self.client_ec2.describe_security_groups(GroupIds=[resource_id])
        except:
            self.logging.error(
                f"Could not describe default Security Group '{resource_id}'."
            )
            self.logging.error(sys.exc_info()[1])
            return False

        for security_group in response.get("SecurityGroups"):
            # revoke egress rule
            try:
                self.client_ec2.revoke_security_group_egress(
                    GroupId=resource_id,
                    IpPermissions=security_group.get("IpPermissionsEgress"),
                )
                self.logging.info(
                    f"Revoked all egress rules for default Security Group '{resource_id}'."
                )
            except:
                self.logging.error(
                    f"Could not revoke egress rules for default Security Group '{resource_id}'."
                )
                self.logging.error(sys.exc_info()[1])
                return False

            # revoke ingress rules
            try:
                self.client_ec2.revoke_security_group_ingress(
                    GroupId=resource_id,
                    IpPermissions=security_group.get("IpPermissions"),
                )
                self.logging.info(
                    f"Revoked all ingress rules for default Security Group '{resource_id}'."
                )
            except:
                self.logging.error(
                    f"Could not revoke ingress rules for default Security Group '{resource_id}'."
                )
                self.logging.error(sys.exc_info()[1])
                return False

            return True

    def vpc_flow_logs_enabled(self, resource_id):
        """Enables VPC Flow Logs by creating a new S3 Bucket with the name "<resource_id>-flow-logs".
        
        Arguments:
            resource_id {string} -- VPC ID
        
        Returns:
            boolean -- True if remediation was successful
        """
        log_bucket = f"{self.account_number}-{self.region}-flow-logs"

        # create new Bucket for logs
        try:
            self.client_s3.create_bucket(
                ACL="log-delivery-write",
                Bucket=log_bucket,
                CreateBucketConfiguration={"LocationConstraint": self.region},
            )

            self.logging.info(
                f"Created new S3 Bucket '{log_bucket}' "
                f"for storing server access logs for S3 Bucket '{resource_id}'."
            )
        except self.client_s3.exceptions.BucketAlreadyOwnedByYou:
            self.logging.info(
                f"Skipped creation of S3 Bucket '{log_bucket}' as it already exists."
            )
        except:
            self.logging.error(
                f"Could not create new S3 Bucket '{log_bucket}' "
                f"for storing VPC Flow Logs for VPC '{resource_id}'."
            )
            self.logging.error(sys.exc_info()[1])
            return False

        # add VPC flow logs
        try:
            self.client_ec2.create_flow_logs(
                ResourceIds=[resource_id],
                ResourceType="VPC",
                TrafficType="REJECT",
                LogDestinationType="s3",
                LogDestination=f"arn:aws:s3:::{log_bucket}/{resource_id}",
            )

            self.logging.info(
                f"VPC Flow Logs have been enabled for "
                f"VPC '{resource_id}' to S3 Bucket '{log_bucket}/{resource_id}'."
            )
            return True
        except:
            self.logging.error(
                f"Could not enable VPC Flow Logs for "
                f"VPC '{resource_id}' to S3 Bucket '{log_bucket}/{resource_id}'."
            )
            self.logging.error(sys.exc_info()[1])
            return False

    # ROLLBACK METHODS

    # IAM
    def delete_log_group(self, log_group_name):
        try:
            self.client_logs.delete_log_group(logGroupName=log_group_name)
            self.logging.info(f"Deleted CloudWatch Log Group '{log_group_name}'.")
        except:
            self.logging.error(
                f"Could not delete CloudWatch Log Group '{log_group_name}'."
            )
            self.logging.error(sys.exc_info()[1])

    def delete_role(self, role_name):
        try:
            self.client_iam.delete_role(RoleName=role_name)
            self.logging.info(f"Deleted IAM Role '{role_name}'.")
        except:
            self.logging.error(f"Could not delete IAM Role '{role_name}'.")
            self.logging.error(sys.exc_info()[1])

    def delete_role_policy(self, role_name, iam_policy_name):
        try:
            self.client_iam.delete_role_policy(
                RoleName=role_name, PolicyName=iam_policy_name
            )
            self.logging.info(
                f"Deleted IAM Policy '{iam_policy_name}' from IAM Role '{role_name}'."
            )
        except:
            self.logging.error(
                f"Could not delete IAM Policy '{iam_policy_name}' from IAM Role '{role_name}'."
            )
            self.logging.error(sys.exc_info()[1])

    # KMS
    def schedule_key_deletion(self, key_id):
        try:
            self.client_kms.schedule_key_deletion(KeyId=key_id, PendingWindowInDays=7)
            self.logging.info(
                f"Scheduled KMS Customer Managed Key '{key_id}' for deletion."
            )
        except:
            self.logging.error(f"Could not delete KMS Customer Managed Key '{key_id}'.")

    # S3
    def delete_bucket(self, bucket):
        try:
            self.client_s3.delete_bucket(Bucket=bucket)
            self.logging.info(f"Deleted S3 Bucket '{bucket}'.")
        except:
            self.logging.error(f"Could not delete S3 Bucket '{bucket}'.")

    # STATIC METHODS

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
