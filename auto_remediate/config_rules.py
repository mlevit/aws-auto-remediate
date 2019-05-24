import json
import sys

import boto3
from botocore.exceptions import ClientError


class ConfigRules:
    def __init__(self, logging):
        self.logging = logging

        self._client_rds = None
        self._client_s3 = None
        self._client_sts = None

    @property
    def client_rds(self):
        if not self._client_rds:
            self._client_rds = boto3.client("rds")
        return self._client_rds

    @property
    def client_s3(self):
        if not self._client_s3:
            self._client_s3 = boto3.client("s3")
        return self._client_s3

    @property
    def client_sts(self):
        if not self._client_sts:
            self._client_sts = boto3.client("sts")
        return self._client_sts

    @property
    def account_number(self):
        return self.client_sts.get_caller_identity()["Account"]

    @property
    def account_arn(self):
        return self.client_sts.get_caller_identity()["Arn"]

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
            paginator = self.client_rds.get_paginator("describe_db_instances")
            response = paginator.paginate(DBInstanceIdentifier=resource_id)
        except:
            self.logging.error("Could not describe RDS DB Instances.")
            return False
        else:
            for instance in response["DBInstances"]:
                try:
                    self.client_rds.modify_db_instance(
                        DBInstanceIdentifier=instance["DBInstanceIdentifier"],
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
        """Enables Server-side Encryption for an S3 Bucket
        
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
                f"Enabled Server-side Encryption for S3 Bucket '{resource_id}'."
            )
            return True
        except:
            self.logging.info(
                f"Could not enable Server-side Encryption for S3 Bucket '{resource_id}'."
            )
            self.logging.error(sys.exc_info()[1])
            return False

    def s3_bucket_ssl_requests_only(self, resource_id):
        """Adds Bucket Policy to force SSL only connections
        
        Arguments:
            resource_id {string} -- S3 Bucket name
        
        Returns:
            boolean -- True if remediation was successful
        """

        # get SSL policy
        policy_file = "auto_remediate/data/s3_bucket_ssl_requests_only_policy.json"
        with open(policy_file, "r") as file:
            policy = file.read()

        policy = json.loads(policy.replace("_BUCKET_", resource_id))

        try:
            response = self.client_s3.get_bucket_policy(Bucket=resource_id)
        except ClientError as error:
            if error.response["Error"]["Code"] == "NoSuchBucketPolicy":
                return self.set_bucket_policy(resource_id, json.dumps(policy))
            else:
                self.logging.error(
                    f"Could not set SSL requests only policy to S3 Bucket '{resource_id}'."
                )
                self.logging.error(sys.exc_info()[1])
                return False
        except:
            self.logging.error(
                f"Could not retrieve existing policy to S3 Bucket '{resource_id}'."
            )
        else:
            existing_policy = json.loads(response["Policy"])
            existing_policy["Statement"].append(policy["Statement"][0])

            return self.set_bucket_policy(resource_id, json.dumps(existing_policy))

    def set_bucket_policy(self, bucket, policy):
        """Attempts to set an S3 Bucket Policy. If returned error is Access Denied, 
        then the Public Access Block is removed before placing a new S3 Bucket Policy
        
        Arguments:
            bucket {string} -- S3 Bucket Name
            policy {string} -- S3 Bucket Policy
        
        Returns:
            boolean -- True if S3 Bucket Policy was set
        """
        try:
            self.client_s3.put_bucket_policy(Bucket=bucket, Policy=policy)
            self.logging.info(f"Set SSL requests only policy to S3 Bucket '{bucket}'.")
            return True
        except ClientError as error:
            if error.response["Error"]["Code"] == "AccessDenied":
                try:
                    # disable Public Access Block
                    self.client_s3.put_public_access_block(
                        Bucket=bucket,
                        PublicAccessBlockConfiguration={
                            "BlockPublicPolicy": False,
                            "RestrictPublicBuckets": False,
                        },
                    )

                    # put Bucket Policy
                    self.client_s3.put_bucket_policy(Bucket=bucket, Policy=policy)

                    # enable Public Access Block
                    self.client_s3.put_public_access_block(
                        Bucket=bucket,
                        PublicAccessBlockConfiguration={
                            "BlockPublicPolicy": True,
                            "RestrictPublicBuckets": True,
                        },
                    )

                    self.logging.info(
                        f"Set SSL requests only policy to S3 Bucket '{bucket}'."
                    )
                    return True
                except:
                    self.logging.error(
                        f"Could not set SSL requests only policy to S3 Bucket '{bucket}'."
                    )
                    self.logging.error(sys.exc_info()[1])
                    return False
            else:
                self.logging.error(
                    f"Could not set SSL requests only policy to S3 Bucket '{bucket}'."
                )
                self.logging.error(sys.exc_info()[1])
                return False
        except:
            self.logging.error(
                f"Could not set SSL requests only policy to S3 Bucket '{bucket}'."
            )
            self.logging.error(sys.exc_info()[1])
            return False
