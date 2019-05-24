import sys

import boto3


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

    @property
    def client_s3(self):
        if not self._client_s3:
            self._client_s3 = boto3.client("s3")
        return self._client_s3

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
                f"Enabled Service Side Encryption for S3 Bucket '{resource_id}'."
            )
            return True
        except:
            self.logging.info(
                f"Could not enable Service Side Encryption for S3 Bucket '{resource_id}'."
            )
            self.logging.error(sys.exc_info()[1])
            return False
