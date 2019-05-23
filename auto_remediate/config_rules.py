import json
import sys

import boto3
from botocore.exceptions import ClientError


class ConfigRules:
    def __init__(self, logging):
        self.logging = logging

        self._client_rds = None
        self._client_s3 = None

    @property
    def client_rds(self):
        if not self._client_rds:
            self._client_rds = boto3.client("rds")
        return self._client_rds

    @client_rds.setter
    def client_rds(self, client):
        self._client_rds = client

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
        return self.client_sts.get_caller_identity().get("Account")

    @property
    def account_arn(self):
        return self.client_sts.get_caller_identity().get("Arn")

    @property
    def region(self):
        if self.client_sts.meta.region_name != "aws-global":
            return self.client_sts.meta.region_name
        else:
            return "us-east-1"

    def rds_instance_public_access_check(self, resource_id):
        """Sets Publicly Accessible option to False for public RDS Instances
        
        Arguments:
            resource_id {DbiResourceId} -- The AWS Region-unique, immutable identifier for the DB instance
        
        Returns:
            boolean -- True if remediation was successful
        """
        try:
            response = self.client_rds.describe_db_instances()
        except:
            self.logging.error("Could not describe RDS DB Instances.")
            return False
        else:
            for instance in response.get("DBInstances"):
                if resource_id == instance.get("DbiResourceId"):
                    try:
                        self.client_rds.modify_db_instance(
                            DBInstanceIdentifier=instance.get("DBInstanceIdentifier"),
                            PubliclyAccessible=False,
                        )
                        self.logging.info(
                            f"Disabled Public Accessibility for RDS Instance '{resource_id}'."
                        )
                        return True
                    except:
                        self.logging.error(
                            f"Could not disable Public Accessibility for RDS Instance '{resource_id}'."
                        )
                        self.logging.error(sys.exc_info()[1])
                        return False

    def s3_bucket_server_side_encryption_enabled(self, resource_id):
        """Enables Service Side Encruption for an S3 Bucket
        
        Arguments:
            resource_id {string} -- S3 Bucket name
        
        Returns:
            boolean -- True if remediation is successful
        """
        try:
            self.client_s3.put_bucket_encryption(
                Bucket=resource_id,
                ServerSideEncryptionConfiguration={
                    "Rules": [
                        {
                            "ApplyServerSideEncryptionByDefault": {
                                "SSEAlgorithm": "AES256"
                            }
                        }
                    ]
                },
            )
            self.logging.info(
                f"Enabled Service Side Encryption for S3 Bucket '{resource_id}'."
            )
            return True
        except:
            self.logging.info(
                f"Could not enable Service Side Encryption for S3 Bucket '{resource_id}'."
            )
            self.logging.error(sys.exc_info()[1])
            return False

    def s3_bucket_ssl_requests_only(self, resource_id):
        policy_file = "auto_remediate/data/s3_bucket_ssl_requests_only_policy.json"
        with open(policy_file, "r") as file:
            policy = file.read()

        policy = json.loads(policy.replace("_BUCKET_", resource_id))

        block_public_policy = None
        restrict_public_buckets = None

        try:
            response = self.client_s3.get_public_access_block(Bucket=resource_id)
        except ClientError as error:
            if (
                error.response["Error"]["Code"]
                == "NoSuchPublicAccessBlockConfiguration"
            ):
                ...
            else:
                self.logging.error(
                    f"Could not retrieve public access block details for S3 Bucket '{resource_id}'."
                )
                self.logging.error(sys.exc_info()[1])
                return False
        except:
            self.logging.error(
                f"Could not retrieve public access block details for S3 Bucket '{resource_id}'."
            )
            self.logging.error(sys.exc_info()[1])
            return False
        else:
            block_public_acls = response.get("PublicAccessBlockConfiguration").get(
                "BlockPublicAcls"
            )
            ignore_public_acls = response.get("PublicAccessBlockConfiguration").get(
                "IgnorePublicAcls"
            )
            block_public_policy = response.get("PublicAccessBlockConfiguration").get(
                "BlockPublicPolicy"
            )
            restrict_public_buckets = response.get(
                "PublicAccessBlockConfiguration"
            ).get("RestrictPublicBuckets")

            if block_public_policy or restrict_public_buckets:
                # remove Bucket Policy restriction
                try:
                    self.client_s3.put_public_access_block(
                        Bucket=resource_id,
                        PublicAccessBlockConfiguration={
                            "BlockPublicPolicy": False,
                            "RestrictPublicBuckets": False,
                        },
                    )
                    self.logging.info(
                        f"Disabled public access block for S3 Bucket '{resource_id}'."
                    )
                except:
                    self.logging.error(
                        f"Could not disable public access block for S3 Bucket '{resource_id}'."
                    )
                    self.logging.error(sys.exc_info()[1])
                    return False

        try:
            response = self.client_s3.get_bucket_policy(Bucket=resource_id)
        except ClientError as error:
            if error.response["Error"]["Code"] == "NoSuchBucketPolicy":
                try:
                    self.client_s3.put_bucket_policy(Bucket=resource_id, Policy=policy)
                    self.logging.info(
                        f"Set SSL requests only policy to S3 Bucket '{resource_id}'."
                    )
                except:
                    self.logging.error(
                        f"Could not set SSL requests only policy to S3 Bucket '{resource_id}'."
                    )
                    self.logging.error(sys.exc_info()[1])
                    return False
            else:
                self.logging.error(
                    f"Could not retrieve existing policy to S3 Bucket '{resource_id}'."
                )
                self.logging.error(sys.exc_info()[1])
                return False
        except:
            self.logging.error(
                f"Could not retrieve existing policy to S3 Bucket '{resource_id}'."
            )
            self.logging.error(sys.exc_info()[1])
            return False
        else:
            existing_policy = json.loads(response.get("Policy"))

            # insert SSL policy
            existing_policy.get("Statement").append(policy.get("Statement")[0])

            try:
                self.client_s3.put_bucket_policy(
                    Bucket=resource_id, Policy=json.dumps(existing_policy)
                )
                self.logging.info(
                    f"Added SSL requests only policy to S3 Bucket '{resource_id}'."
                )
            except:
                self.logging.error(
                    f"Could not set SSL requests only policy to S3 Bucket '{resource_id}'."
                )
                self.logging.error(sys.exc_info()[1])
                return False

        # add Bucket Policy restriction
        if block_public_policy or restrict_public_buckets:
            try:
                self.client_s3.put_public_access_block(
                    Bucket=resource_id,
                    PublicAccessBlockConfiguration={
                        "BlockPublicAcls": block_public_acls,
                        "IgnorePublicAcls": ignore_public_acls,
                        "BlockPublicPolicy": block_public_policy,
                        "RestrictPublicBuckets": restrict_public_buckets,
                    },
                )
                self.logging.info(
                    f"Enabled public access block for S3 Bucket '{resource_id}'."
                )
                return True
            except:
                self.logging.error(
                    f"Could not enable public access block for S3 Bucket '{resource_id}'."
                )
                self.logging.error(sys.exc_info()[1])
                return False
        else:
            return True
