# Coverage

Below tables represent the coverage of Auto Remediate. Automated testing of Auto Remediate is done using the [Moto](https://github.com/spulec/moto) Python library.

## Security Hub Rules

Development coverage: **100% (24/24)**

Test coverage: **29% (7/24)**

| Rule                                                   | Development Status | Testing Status  |
| ------------------------------------------------------ | ------------------ | --------------- |
| securityhub-access-keys-rotated                        | Done               |                 |
| securityhub-cloud-trail-cloud-watch-logs-enabled       | Done ​              | No Moto support |
| securityhub-cloud-trail-encryption-enabled             | Done               | No Moto support |
| securityhub-cloud-trail-log-file-validation            | Done               | No Moto support |
| securityhub-cmk-backing-key-rotation-enabled           | Done               | Done            |
| securityhub-iam-password-policy-ensure-expires         | Done               | No Moto support |
| securityhub-iam-password-policy-lowercase-letter-check | Done               | No Moto support |
| securityhub-iam-password-policy-minimum-length-check   | Done               | No Moto support |
| securityhub-iam-password-policy-number-check           | Done               | No Moto support |
| securityhub-iam-password-policy-prevent-reuse-check    | Done               | No Moto support |
| securityhub-iam-password-policy-symbol-check           | Done               | No Moto support |
| securityhub-iam-password-policy-uppercase-letter-check | Done               | No Moto support |
| securityhub-iam-policy-no-statements-with-admin-access | Done               |                 |
| securityhub-iam-root-access-key-check                  | Not possible       | N/A             |
| securityhub-iam-user-no-policies-check                 | Done               | Done            |
| securityhub-iam-user-unused-credentials-check          | Done               |                 |
| securityhub-mfa-enabled-for-iam-console-access         | Done               | Done            |
| securityhub-multi-region-cloud-trail-enabled           | Done               | No Moto support |
| securityhub-restricted-rdp                             | Done               | Done            |
| securityhub-restricted-ssh                             | Done               | Done            |
| securityhub-root-account-hardware-mfa-enabled          | Not possible       | N/A             |
| securityhub-root-account-mfa-enabled                   | Not possible       | N/A             |
| securityhub-s3-bucket-logging-enabled                  | Done               | No Moto support |
| securityhub-s3-bucket-public-read-prohibited           | Done               | Done            |
| securityhub-s3-bucket-public-write-prohibited          | Done               | Done            |
| securityhub-vpc-default-security-group-closed          | Done               |                 |
| securityhub-vpc-flow-logs-enabled                      | Done               | No Moto support |

## AWS Config Managed Rules

Development coverage: **2.5% (1/40)**

Test coverage: **0% (0/40)**

| Rule                                                    | Development Status | Testing Status |
| ------------------------------------------------------- | ------------------ | -------------- |
| access-keys-rotated                                     | Security Hub       |                |
| cloudtrail-enabled                                      |                    |                |
| db-instance-backup-enabled                              |                    |                |
| dynamodb-table-encryption-enabled                       |                    |                |
| ec2-instances-in-vpc                                    |                    |                |
| cloud-trail-cloud-watch-logs-enabled                    | Security Hub       |                |
| cloud-trail-encryption-enabled                          | Security Hub       |                |
| cloud-trail-log-file-validation-enabled                 |                    |                |
| encrypted-volumes                                       |                    |                |
| guardduty-enabled-centralized                           |                    |                |
| lambda-function-public-access-prohibited                |                    |                |
| rds-multi-az-support                                    |                    |                |
| rds-snapshots-public-prohibited                         |                    |                |
| rds-storage-encrypted                                   |                    |                |
| cmk-backing-key-rotation-enabled                        | Security Hub       |                |
| s3-bucket-server-side-encryption-enabled                |                    |                |
| s3-bucket-ssl-requests-only                             |                    |                |
| dynamodb-autoscaling-enabled                            |                    |                |
| ec2-instance-detailed-monitoring-enabled                |                    |                |
| ec2-volume-inuse-check                                  |                    |                |
| eip-attached                                            |                    |                |
| elb-logging-enabled                                     |                    |                |
| acm-certificate-expiration-check                        |                    |                |
| approved-amis-by-id                                     |                    |                |
| approved-amis-by-tag                                    |                    |                |
| autoscaling-group-elb-healthcheck-required              |                    |                |
| cloudformation-stack-drift-detection-check              |                    |                |
| cloudformation-stack-notification-check                 |                    |                |
| cloudwatch-alarm-action-check                           |                    |                |
| cloudwatch-alarm-resource-check                         |                    |                |
| rds-instance-public-access-check                        | Done               |                |
| cloudwatch-alarm-settings-check                         |                    |                |
| codebuild-project-envvar-awscred-check                  |                    |                |
| codebuild-project-source-repo-url-check                 |                    |                |
| codepipeline-deployment-count-check                     |                    |                |
| codepipeline-region-fanout-check                        |                    |                |
| desired-instance-tenancy                                |                    |                |
| desired-instance-type                                   |                    |                |
| dynamodb-throughput-limit-check                         |                    |                |
| ebs-optimized-instance                                  |                    |                |
| ec2-instance-managed-by-systems-manager                 |                    |                |
| ec2-managedinstance-applications-blacklisted            |                    |                |
| ec2-managedinstance-applications-required               |                    |                |
| ec2-managedinstance-association-compliance-status-check |                    |                |
| ec2-managedinstance-inventory-blacklisted               |                    |                |
| ec2-managedinstance-patch-compliance-status-check       |                    |                |
| ec2-managedinstance-platform-check                      |                    |                |
| elb-acm-certificate-required                            |                    |                |
| iam-password-policy                                     | Security Hub       |                |
| elb-custom-security-policy-ssl-check                    |                    |                |
| iam-policy-no-statements-with-admin-access              | Security Hub       |                |
| elb-predefined-security-policy-ssl-check                |                    |                |
| iam-root-access-key-check                               | Security Hub       |                |
| fms-shield-resource-policy-check                        |                    |                |
| iam-user-mfa-enabled                                    | Security Hub       |                |
| iam-user-no-policies-check                              | Security Hub       |                |
| iam-user-unused-credentials-check                       | Security Hub       |                |
| fms-webacl-resource-policy-check                        |                    |                |
| fms-webacl-rulegroup-association-check                  |                    |                |
| mfa-enabled-for-iam-console-access                      | Security Hub       |                |
| multi-region-cloud-trail-enabled                        | Security Hub       |                |
| iam-group-has-users-check                               |                    |                |
| iam-policy-blacklisted-check                            |                    |                |
| iam-role-managed-policy-check                           |                    |                |
| iam-user-group-membership-check                         |                    |                |
| lambda-function-settings-check                          |                    |                |
| redshift-cluster-configuration-check                    |                    |                |
| redshift-cluster-maintenancesettings-check              |                    |                |
| restricted-ssh                                          | Security Hub       |                |
| root-account-hardware-mfa-enabled                       | Security Hub       |                |
| root-account-mfa-enabled                                | Security Hub       |                |
| required-tags                                           |                    |                |
| s3-bucket-logging-enabled                               | Security Hub       |                |
| restricted-common-ports                                 |                    |                |
| s3-blacklisted-actions-prohibited                       |                    |                |
| s3-bucket-public-read-prohibited                        | Security Hub       |                |
| s3-bucket-public-write-prohibited                       | Security Hub       |                |
| s3-bucket-policy-grantee-check                          |                    |                |
| s3-bucket-policy-not-more-permissive                    |                    |                |
| s3-bucket-replication-enabled                           |                    |                |
| s3-bucket-versioning-enabled                            |                    |                |
| vpc-default-security-group-closed                       | Security Hub       |                |
| vpc-flow-logs-enabled                                   | Security Hub       |                |
