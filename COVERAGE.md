# Coverage

Below tables represent the coverage of Auto Remediate. Automated testing of Auto Remediate is done using the [Moto](https://github.com/spulec/moto) Python library.

## Security Hub Rules

Development coverage: **24 of 24**

Test coverage: **10 of 24**

| Rule                                                   | Development Status | Testing Status  |
| ------------------------------------------------------ | ------------------ | --------------- |
| securityhub-access-keys-rotated                        | Done               | Done            |
| securityhub-cloud-trail-cloud-watch-logs-enabled       | Done ​             | No Moto support |
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
| securityhub-iam-policy-no-statements-with-admin-access | Done               | Done            |
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
| securityhub-vpc-default-security-group-closed          | Done               | Done            |
| securityhub-vpc-flow-logs-enabled                      | Done               | No Moto support |

## AWS Config Managed Rules

Development coverage: **1 of 40**

Test coverage: **0 of 40**

| Rule                                                                                                                                                                             | Priority | Development Status | Testing Status  |
| -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | -------- | ------------------ | --------------- |
| [access-keys-rotated](https://docs.aws.amazon.com/config/latest/developerguide/access-keys-rotated.html)                                                                         |          | Security Hub       | N/A             |
| [acm-certificate-expiration-check](https://docs.aws.amazon.com/config/latest/developerguide/acm-certificate-expiration-check.html)                                               |          |                    |                 |
| [approved-amis-by-id](https://docs.aws.amazon.com/config/latest/developerguide/approved-amis-by-id.html)                                                                         |          |                    |                 |
| [approved-amis-by-tag](https://docs.aws.amazon.com/config/latest/developerguide/approved-amis-by-tag.html)                                                                       |          |                    |                 |
| [autoscaling-group-elb-healthcheck-required](https://docs.aws.amazon.com/config/latest/developerguide/autoscaling-group-elb-healthcheck-required.html)                           |          |                    |                 |
| [cloud-trail-cloud-watch-logs-enabled](https://docs.aws.amazon.com/config/latest/developerguide/cloud-trail-cloud-watch-logs-enabled.html)                                       |          | Security Hub       | N/A             |
| [cloud-trail-encryption-enabled](https://docs.aws.amazon.com/config/latest/developerguide/cloud-trail-encryption-enabled.html)                                                   |          | Security Hub       | N/A             |
| [cloud-trail-log-file-validation-enabled](https://docs.aws.amazon.com/config/latest/developerguide/cloud-trail-log-file-validation-enabled.html)                                 |          |                    |                 |
| [cloudformation-stack-drift-detection-check](https://docs.aws.amazon.com/config/latest/developerguide/cloudformation-stack-drift-detection-check.html)                           |          |                    |                 |
| [cloudformation-stack-notification-check](https://docs.aws.amazon.com/config/latest/developerguide/cloudformation-stack-notification-check.html)                                 |          |                    |                 |
| [cloudtrail-enabled](https://docs.aws.amazon.com/config/latest/developerguide/cloudtrail-enabled.html)                                                                           | 1        |                    |                 |
| [cloudwatch-alarm-action-check](https://docs.aws.amazon.com/config/latest/developerguide/cloudwatch-alarm-action-check.html)                                                     |          |                    |                 |
| [cloudwatch-alarm-resource-check](https://docs.aws.amazon.com/config/latest/developerguide/cloudwatch-alarm-resource-check.html)                                                 |          |                    |                 |
| [cloudwatch-alarm-settings-check](https://docs.aws.amazon.com/config/latest/developerguide/cloudwatch-alarm-settings-check.html)                                                 |          |                    |                 |
| [cmk-backing-key-rotation-enabled](https://docs.aws.amazon.com/config/latest/developerguide/cmk-backing-key-rotation-enabled.html)                                               |          | Security Hub       | N/A             |
| [codebuild-project-envvar-awscred-check](https://docs.aws.amazon.com/config/latest/developerguide/codebuild-project-envvar-awscred-check.html)                                   |          |                    |                 |
| [codebuild-project-source-repo-url-check](https://docs.aws.amazon.com/config/latest/developerguide/codebuild-project-source-repo-url-check.html)                                 |          |                    |                 |
| [codepipeline-deployment-count-check](https://docs.aws.amazon.com/config/latest/developerguide/codepipeline-deployment-count-check.html)                                         |          |                    |                 |
| [codepipeline-region-fanout-check](https://docs.aws.amazon.com/config/latest/developerguide/codepipeline-region-fanout-check.html)                                               |          |                    |                 |
| [db-instance-backup-enabled](https://docs.aws.amazon.com/config/latest/developerguide/db-instance-backup-enabled.html)                                                           | 1        |                    |                 |
| [desired-instance-tenancy](https://docs.aws.amazon.com/config/latest/developerguide/desired-instance-tenancy.html)                                                               |          |                    |                 |
| [desired-instance-type](https://docs.aws.amazon.com/config/latest/developerguide/desired-instance-type.html)                                                                     |          |                    |                 |
| [dynamodb-autoscaling-enabled](https://docs.aws.amazon.com/config/latest/developerguide/dynamodb-autoscaling-enabled.html)                                                       | 2        |                    |                 |
| [dynamodb-table-encryption-enabled](https://docs.aws.amazon.com/config/latest/developerguide/dynamodb-table-encryption-enabled.html)                                             | 1        |                    |                 |
| [dynamodb-throughput-limit-check](https://docs.aws.amazon.com/config/latest/developerguide/dynamodb-throughput-limit-check.html)                                                 |          |                    |                 |
| [ebs-optimized-instance](https://docs.aws.amazon.com/config/latest/developerguide/ebs-optimized-instance.html)                                                                   |          |                    |                 |
| [ec2-instance-detailed-monitoring-enabled](https://docs.aws.amazon.com/config/latest/developerguide/ec2-instance-detailed-monitoring-enabled.html)                               | 2        |                    |                 |
| [ec2-instance-managed-by-systems-manager](https://docs.aws.amazon.com/config/latest/developerguide/ec2-instance-managed-by-systems-manager.html)                                 |          |                    |                 |
| [ec2-instances-in-vpc](https://docs.aws.amazon.com/config/latest/developerguide/ec2-instances-in-vpc.html)                                                                       | 1        |                    |                 |
| [ec2-managedinstance-applications-blacklisted](https://docs.aws.amazon.com/config/latest/developerguide/ec2-managedinstance-applications-blacklisted.html)                       |          |                    |                 |
| [ec2-managedinstance-applications-required](https://docs.aws.amazon.com/config/latest/developerguide/ec2-managedinstance-applications-required.html)                             |          |                    |                 |
| [ec2-managedinstance-association-compliance-status-check](https://docs.aws.amazon.com/config/latest/developerguide/ec2-managedinstance-association-compliance-status-check.html) |          |                    |                 |
| [ec2-managedinstance-inventory-blacklisted](https://docs.aws.amazon.com/config/latest/developerguide/ec2-managedinstance-inventory-blacklisted.html)                             |          |                    |                 |
| [ec2-managedinstance-patch-compliance-status-check](https://docs.aws.amazon.com/config/latest/developerguide/ec2-managedinstance-patch-compliance-status-check.html)             |          |                    |                 |
| [ec2-managedinstance-platform-check](https://docs.aws.amazon.com/config/latest/developerguide/ec2-managedinstance-platform-check.html)                                           |          |                    |                 |
| [ec2-volume-inuse-check](https://docs.aws.amazon.com/config/latest/developerguide/ec2-volume-inuse-check.html)                                                                   | 2        |                    |                 |
| [eip-attached](https://docs.aws.amazon.com/config/latest/developerguide/eip-attached.html)                                                                                       | 2        |                    |                 |
| [elb-acm-certificate-required](https://docs.aws.amazon.com/config/latest/developerguide/elb-acm-certificate-required.html)                                                       |          |                    |                 |
| [elb-custom-security-policy-ssl-check](https://docs.aws.amazon.com/config/latest/developerguide/elb-custom-security-policy-ssl-check.html)                                       |          |                    |                 |
| [elb-logging-enabled](https://docs.aws.amazon.com/config/latest/developerguide/elb-logging-enabled.html)                                                                         | 2        |                    |                 |
| [elb-predefined-security-policy-ssl-check](https://docs.aws.amazon.com/config/latest/developerguide/elb-predefined-security-policy-ssl-check.html)                               |          |                    |                 |
| [encrypted-volumes](https://docs.aws.amazon.com/config/latest/developerguide/encrypted-volumes.html)                                                                             | 1        | Not feasible       | N/A             |
| [fms-shield-resource-policy-check](https://docs.aws.amazon.com/config/latest/developerguide/fms-shield-resource-policy-check.html)                                               |          |                    |                 |
| [fms-webacl-resource-policy-check](https://docs.aws.amazon.com/config/latest/developerguide/fms-webacl-resource-policy-check.html)                                               |          |                    |                 |
| [fms-webacl-rulegroup-association-check](https://docs.aws.amazon.com/config/latest/developerguide/fms-webacl-rulegroup-association-check.html)                                   |          |                    |                 |
| [guardduty-enabled-centralized](https://docs.aws.amazon.com/config/latest/developerguide/guardduty-enabled-centralized.html)                                                     | 1        |                    |                 |
| [iam-group-has-users-check](https://docs.aws.amazon.com/config/latest/developerguide/iam-group-has-users-check.html)                                                             |          |                    |                 |
| [iam-password-policy](https://docs.aws.amazon.com/config/latest/developerguide/iam-password-policy.html)                                                                         |          |                    |                 |
| [iam-policy-blacklisted-check](https://docs.aws.amazon.com/config/latest/developerguide/iam-policy-blacklisted-check.html)                                                       |          |                    |                 |
| [iam-policy-no-statements-with-admin-access](https://docs.aws.amazon.com/config/latest/developerguide/iam-policy-no-statements-with-admin-access.html)                           |          | Security Hub       | N/A             |
| [iam-role-managed-policy-check](https://docs.aws.amazon.com/config/latest/developerguide/iam-role-managed-policy-check.html)                                                     |          |                    |                 |
| [iam-root-access-key-check](https://docs.aws.amazon.com/config/latest/developerguide/iam-root-access-key-check.html)                                                             |          | Security Hub       | N/A             |
| [iam-user-group-membership-check](https://docs.aws.amazon.com/config/latest/developerguide/iam-user-group-membership-check.html)                                                 |          |                    |                 |
| [iam-user-mfa-enabled](https://docs.aws.amazon.com/config/latest/developerguide/iam-user-mfa-enabled.html)                                                                       |          |                    |                 |
| [iam-user-no-policies-check](https://docs.aws.amazon.com/config/latest/developerguide/iam-user-no-policies-check.html)                                                           |          | Security Hub       | N/A             |
| [iam-user-unused-credentials-check](https://docs.aws.amazon.com/config/latest/developerguide/iam-user-unused-credentials-check.html)                                             |          | Security Hub       | N/A             |
| [lambda-function-public-access-prohibited](https://docs.aws.amazon.com/config/latest/developerguide/lambda-function-public-access-prohibited.html)                               | 1        |                    |                 |
| [lambda-function-settings-check](https://docs.aws.amazon.com/config/latest/developerguide/lambda-function-settings-check.html)                                                   |          |                    |                 |
| [mfa-enabled-for-iam-console-access](https://docs.aws.amazon.com/config/latest/developerguide/mfa-enabled-for-iam-console-access.html)                                           |          | Security Hub       | N/A             |
| [multi-region-cloud-trail-enabled](https://docs.aws.amazon.com/config/latest/developerguide/multi-region-cloud-trail-enabled.html)                                               |          | Security Hub       | N/A             |
| [rds-instance-public-access-check](https://docs.aws.amazon.com/config/latest/developerguide/rds-instance-public-access-check.html)                                               |          | Done               |                 |
| [rds-multi-az-support](https://docs.aws.amazon.com/config/latest/developerguide/rds-multi-az-support.html)                                                                       | 1        |                    |                 |
| [rds-snapshots-public-prohibited](https://docs.aws.amazon.com/config/latest/developerguide/rds-snapshots-public-prohibited.html)                                                 | 1        |                    |                 |
| [rds-storage-encrypted](https://docs.aws.amazon.com/config/latest/developerguide/rds-storage-encrypted.html)                                                                     | 1        |                    |                 |
| [redshift-cluster-configuration-check](https://docs.aws.amazon.com/config/latest/developerguide/redshift-cluster-configuration-check.html)                                       |          |                    |                 |
| [redshift-cluster-maintenancesettings-check](https://docs.aws.amazon.com/config/latest/developerguide/redshift-cluster-maintenancesettings-check.html)                           |          |                    |                 |
| [required-tags](https://docs.aws.amazon.com/config/latest/developerguide/required-tags.html)                                                                                     |          |                    |                 |
| [restricted-common-ports](https://docs.aws.amazon.com/config/latest/developerguide/restricted-common-ports.html)                                                                 |          |                    |                 |
| [restricted-ssh](https://docs.aws.amazon.com/config/latest/developerguide/restricted-ssh.html)                                                                                   |          | Security Hub       | N/A             |
| [root-account-hardware-mfa-enabled](https://docs.aws.amazon.com/config/latest/developerguide/root-account-hardware-mfa-enabled.html)                                             |          | Security Hub       | N/A             |
| [root-account-mfa-enabled](https://docs.aws.amazon.com/config/latest/developerguide/root-account-mfa-enabled.html)                                                               |          | Security Hub       | N/A             |
| [s3-blacklisted-actions-prohibited](https://docs.aws.amazon.com/config/latest/developerguide/s3-blacklisted-actions-prohibited.html)                                             |          |                    |                 |
| [s3-bucket-logging-enabled](https://docs.aws.amazon.com/config/latest/developerguide/s3-bucket-logging-enabled.html)                                                             |          | Security Hub       | N/A             |
| [s3-bucket-policy-grantee-check](https://docs.aws.amazon.com/config/latest/developerguide/s3-bucket-policy-grantee-check.html)                                                   |          |                    |                 |
| [s3-bucket-policy-not-more-permissive](https://docs.aws.amazon.com/config/latest/developerguide/s3-bucket-policy-not-more-permissive.html)                                       |          |                    |                 |
| [s3-bucket-public-read-prohibited](https://docs.aws.amazon.com/config/latest/developerguide/s3-bucket-public-read-prohibited.html)                                               |          | Security Hub       | N/A             |
| [s3-bucket-public-write-prohibited](https://docs.aws.amazon.com/config/latest/developerguide/s3-bucket-public-write-prohibited.html)                                             |          | Security Hub       | N/A             |
| [s3-bucket-replication-enabled](https://docs.aws.amazon.com/config/latest/developerguide/s3-bucket-replication-enabled.html)                                                     |          |                    |                 |
| [s3-bucket-server-side-encryption-enabled](https://docs.aws.amazon.com/config/latest/developerguide/s3-bucket-server-side-encryption-enabled.html)                               | 1        | Done               | No Moto support |
| [s3-bucket-ssl-requests-only](https://docs.aws.amazon.com/config/latest/developerguide/s3-bucket-ssl-requests-only.html)                                                         | 1        | Done               |                 |
| [s3-bucket-versioning-enabled](https://docs.aws.amazon.com/config/latest/developerguide/s3-bucket-versioning-enabled.html)                                                       |          |                    |                 |
| [vpc-default-security-group-closed](https://docs.aws.amazon.com/config/latest/developerguide/vpc-default-security-group-closed.html)                                             |          | Security Hub       | N/A             |
| [vpc-flow-logs-enabled](https://docs.aws.amazon.com/config/latest/developerguide/vpc-flow-logs-enabled.html)                                                                     |          | Security Hub       | N/A             |
