# AWS Auto Remediate

[![Build Status](https://travis-ci.org/servian/aws-auto-remediate.svg?branch=master)](https://travis-ci.org/servian/aws-auto-remediate) [![Codacy Badge](https://api.codacy.com/project/badge/Grade/5bce55175d32494c89f0648b27719f43)](https://www.codacy.com/app/servian/aws-auto-remediate?utm_source=github.com&utm_medium=referral&utm_content=servian/aws-auto-remediate&utm_campaign=Badge_Grade) [![Codacy Badge](https://api.codacy.com/project/badge/Coverage/5bce55175d32494c89f0648b27719f43)](https://www.codacy.com/app/servian/aws-auto-remediate?utm_source=github.com&utm_medium=referral&utm_content=servian/aws-auto-remediate&utm_campaign=Badge_Coverage)

![Release](https://img.shields.io/github/release/servian/aws-auto-remediate.svg) ![Pre-release Date](https://img.shields.io/github/release-date-pre/servian/aws-auto-remediate.svg)

![Language](https://img.shields.io/github/languages/top/servian/aws-auto-remediate.svg) [![serverless](http://public.serverless.com/badges/v3.svg)](http://www.serverless.com) [![Python Black](https://img.shields.io/badge/code%20style-black-000000.svg?label=Python%20code%20style)](https://github.com/python/black) [![code style: prettier](https://img.shields.io/badge/code_style-prettier-ff69b4.svg?label=Markdown%2FYAML%20code%20style)](https://github.com/prettier/prettier)

Open source application to instantly remediate common security issues through the use of AWS Config.

![auto-remediate](images/auto-remediate.svg)

## Table of Contents

- [About](#about)
- [Setup](#setup)
  - [Deployment](#deployment)
  - [Update](#update)
  - [Removal](#removal)
- [Settings](#settings)
- [Config Rules](#config-rules)
  - [AWS Config Managed Rules](#aws-config-managed-rules)
  - [AWS Security Hub Rules](#aws-security-hub-rules)
- [Resources](#resources)
- [Coverage](#coverage)
- [Contributing](CONTRIBUTING.md)

## About

### Auto Remediate

The Auto Remediate function is triggered via an SQS Queue `auto-remediate-config-compliance`. The SQS Queue is populated with a compliance payload from AWS Config via a CloudWatch Event `auto-remediate-config-compliance`. The purpose of the CloudWatch Event is to filter out all non-compliance related messages that AWS Config generates.

Once the Lambda function has been triggered it will attempt to remediate the security concern. If the remediation was unsuccessful, the event payload will be sent to the dead letter queue (DQL) SQS Queue `auto-remediate-dlq`. Each time a payload is sent is sent to the DLQ, an attribute `try_count` is incremented to the SQS message. Once that count exceeds `RETRYCOUNT` variable attached to the Lambda Function, the message will no longer be sent to the DLQ.

If no remediation exists for the incoming AWS Config event, the AWS Config payload will be sent to an SNS Topic `auto-remediate-missing-remediation` which can be subscribed to by administrators or other AWS services.

### Auto Remediate DLQ

The Auto Remediate DLQ function is triggered on a schedule (defined in the `serverless.yml` file). When the function is run, it will retrieve messages from SQS Queue `auto-remediate-dlq` and sends the message to the compliance SQS Queue `auto-remediate-config-compliance`.

### Auto Remediate Setup

The Auto Remediate Setup function is triggered manually by the user. The purpose of this function is to invoke CloudFormation Stacks for each of the AWS Config Rules that will monitor for security issues as well as create/insert records into the DynamoDB settings table used to control the actions of the Auto Remediate function.

## Setup

### New Account

Proceed to the [Deployment](#deployment) section below.

### Existing Account

Auto Remediate utilises the compliance event triggers made by AWS Config. Due to the fact that AWS Config will trigger a compliance event **only** when the compliance status of a resource changes state (i.e., COMPLIANT to NON_COMPLIANT or vice versa) it is advised that you **disable** the `CIS AWS Foundations` compliance standards within AWS Security Hub (and ensure all AWS Config rules starting with `securityhub` are removed from your account) before proceeding.

Once AWS Config is cleared of all AWS Security Hub related rules, you may proceed to deploy Auto Remediate and enable the `CIS AWS Foundations` compliance standards within AWS Security Hub.

### Deployment

1.  Install the [Serverless Framework](https://serverless.com/)

```bash
npm install serverless --global
```

2.  Install [AWS CLI](https://aws.amazon.com/cli/)

```bash
pip3 install awscli --upgrade --user
```

3.  Configure the AWS CLI following the instruction at [Quickly Configuring the AWS CLI](https://docs.aws.amazon.com/cli/latest/userguide/cli-chap-configure.html#cli-quick-configuration). Ensure the user you're configuring has the appropriate IAM permissions to create Lambda Functions, S3 Buckets, IAM Roles, and CloudFormation Stacks. It is best for administrators to deploy Auto Remediate.

4.  Install Auto Remediate

```bash
serverless create --template-url https://github.com/servian/aws-auto-remediate --path aws-auto-remediate
```

5.  Change into the Auto Remediate directory

```bash
cd aws-auto-remediate
```

8.  Install Serverless plugins needed for deployment

```bash
serverless plugin install --name serverless-python-requirements
```

```bash
npm install serverless-iam-roles-per-function
```

9.  Deploy Auto Remediate to your AWS account

```bash
serverless deploy [--region <AWS region>] [--aws-profile <AWS CLI profile>]
```

10. Invoke Auto Remediate Setup for the first time to create the necessary AWS Config rules and settings

```bash
serverless invoke -f AutoRemediateSetup [--region <AWS region>] [--aws-profile <AWS CLI profile>]
```

11. Check Auto Remediate Setup logs

```bash
serverless logs -f AutoRemediateSetup [--region <AWS region>] [--aws-profile <AWS CLI profile>]
```

### Update

1.  Remove existing Auto Remediate directory

2.  Install Auto Remediate

```bash
serverless create --template-url https://github.com/servian/aws-auto-remediate --path aws-auto-remediate
```

3.  Deploy Auto Remediate update to your AWS account

```bash
serverless deploy [--region <AWS region>] [--aws-profile <AWS CLI profile>]
```

4.  Invoke Auto Remediate Setup to deploy new AWS Config rules and settings

```bash
serverless invoke --function AutoRemediateSetup [--region <AWS region>] [--aws-profile <AWS CLI profile>]
```

### Removal

Auto Remediate is deployed using the Serverless Framework which under the hood creates an AWS CloudFormation Stack allowing for a clean and simple removal process.

To remove Auto Remediate from your AWS account, follow the below steps:

1.  Change into the Auto Remediate directory

```bash
cd aws-auto-remediate
```

2.  Remove Auto Remediate from your AWS account

```bash
serverless remove [--region <AWS region>] [--aws-profile <AWS CLI profile>]
```

## Settings

Auto Remediate uses a DynamoDB settings table `auto-remediate-settings` that allows the user to control which rule should be remediated by the tool. Once Auto Remediate Setup has been run, head on over to DynamoDB and inspect the `rules` key where you can then set the `remediate` key to `false` if you'd like to disable automatic remediate.

For rules deployed by Auto Remediate Setup (e.g., `auto-remediate-rds-instance-public-access-check`) an extra key `deploy` can be found in the settings table. Although not functional at the moment, this will allow users to control which Auto Remediate deployed rules should be deployed and which should be skipped.

## Config Rules

The tables below detail the auto remediated rules and scenarios.

:warning: All remediations tagged with a warning symbol may break existing functionality.

### AWS Config Managed Rules

#### Database

| Rule                             | Description                                                                                                                                                                                              | Remediation                                          |
| -------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ---------------------------------------------------- |
| RDS Instance Public Access Check | Check whether the Amazon Relational Database Service instances are not publicly accessible.<br />The rule is NON_COMPLIANT if the `publiclyAccessible` field is true in the instance configuration item. | :warning: Sets `publiclyAccessible` field to `False` |

#### Storage

| Rule                                      | Description                                                                                                                                                                            | Remediation                                      |
| ----------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------ |
| S3 Bucket Service Side Encryption Enabled | Checks that your Amazon S3 bucket either has Amazon S3 default encryption enabled or that the S3 bucket policy explicitly denies `put-object` requests without server side encryption. | Enables SSE                                      |
| S3 Bucket SSL Requests Only               | Checks whether S3 buckets have policies that require requests to use Secure Socket Layer (SSL).                                                                                        | Adds Bucket Policy to force SSL only connections |

### AWS Security Hub Rules

#### Compute

| Rule           | Description                                                                                                                                    | Remediation                              |
| -------------- | ---------------------------------------------------------------------------------------------------------------------------------------------- | ---------------------------------------- |
| Restricted RDP | Checks whether the incoming RDP traffic is allowed from `0.0.0.0/0` or `::/0`. This rule is compliant when incoming RDP traffic is restricted. | :warning: Deletes offending inbound rule |
| Restricted SSH | Checks whether the incoming SSH traffic is allowed from `0.0.0.0/0` or `::/0`. This rule is compliant when incoming SSH traffic is restricted. | :warning: Deletes offending inbound rule |

#### Management and Governance

| Rule                                   | Description                                                                                                                                                                                              | Remediation                                                               |
| -------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------- |
| CloudTrail CloudWatch Logs Enabled     | Checks whether AWS CloudTrail trails are configured to send logs to Amazon CloudWatch logs.                                                                                                              | Enables CloudWatch logs to Log Group `cloudtrail/<CloudTrail Name>`       |
| CloudTrail Encryption Enabled          | Ensure CloudTrail logs are encrypted at rest using KMS CMKs.                                                                                                                                             | Enables CloudWatch encryption with KMS CMK `cloudtrail/<CloudTrail Name>` |
| CloudTrail Log File Validation Enabled | Checks whether AWS CloudTrail creates a signed digest file with logs. AWS recommends that the file validation must be enabled on all trails. The rule is NON_COMPLIANT if the validation is not enabled. | Enables CloudTrail Validation                                             |
| Multi Region Cloud Trail Enabled       | Checks that there is at least one multi-region AWS CloudTrail. The rule is NON_COMPLIANT if the trails do not match inputs parameters.                                                                   | Enables Multi Region CloudTrail                                           |

#### Network and Content Delivery

| Rule                              | Description                                                                                                                                                                                                                       | Remediation                                                                                          |
| --------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------- |
| VPC Flow Logs Enables             | Checks whether Amazon Virtual Private Cloud flow logs are found and enabled for Amazon VPC.                                                                                                                                       | Creates new S3 Bucket `<Account Number>-<Region>-flow-logs` for logging with a prefix of `<VPC ID>/` |
| VPC Default Security Group Closed | Checks that the default security group of any Amazon Virtual Private Cloud (VPC) does not allow inbound or outbound traffic. The rule is NON_COMPLIANT if the default security group has one or more inbound or outbound traffic. | Deletes all egress and ingress rules                                                                 |

#### Security, Identity & Compliance

| Rule                                       | Description                                                                                                                                                                                                                                     | Remediation                                                                                                                                                                                                                                         |
| ------------------------------------------ | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Access Keys Rotated                        | Checks whether the active access keys are rotated within the number of days specified in 90 days.                                                                                                                                               | :warning: Deletes Access Key                                                                                                                                                                                                                        |
| Customer Managed Key Rotation Enabled      | Checks that key rotation is enabled for customer created customer master key (CMK).                                                                                                                                                             | Enables key rotation                                                                                                                                                                                                                                |
| IAM Password Policy Ensure Expires         | Checks whether the IAM password policy ensures that passwords expire.                                                                                                                                                                           | Enables password expiration                                                                                                                                                                                                                         |
| IAM Password Policy Lowercase Letter Check | Checks whether the IAM password policy enforces the inclusion of a lowercase letter.                                                                                                                                                            | Enables "Require at least one lowercase letter" option                                                                                                                                                                                              |
| IAM Password Policy Minimum Length Check   | Checks whether the IAM password policy enforces a minimum length.                                                                                                                                                                               | Sets minimum password length to 14.                                                                                                                                                                                                                 |
| IAM Password Policy Number Check           | Checks whether the IAM password policy enforces the inclusion of a number.                                                                                                                                                                      | Enables "Require at least one number" option                                                                                                                                                                                                        |
| IAM Password Policy Prevent Reuse Check    | Checks whether the IAM password policy prevents password reuse.                                                                                                                                                                                 | Sets number of passwords to remember to 24.                                                                                                                                                                                                         |
| IAM Password Policy Symbol Check           | Checks whether the IAM password policy enforces the inclusion of a symbol.                                                                                                                                                                      | Enables "Require at least one non-alphanumeric character" option                                                                                                                                                                                    |
| IAM Password Policy Uppercase Letter Check | Checks whether the account password policy for IAM users requires at least one uppercase character in password.                                                                                                                                 | Enables "Require at least one uppercase letter" option                                                                                                                                                                                              |
| IAM Policy No Statements with Admin Access | Checks whether the default version of AWS Identity and Access Management (IAM) policies do not have administrator access.<br />If any statement has `"Effect": "Allow"` with `"Action": "*"` over `"Resource": "*"`, the rule is NON_COMPLIANT. | :warning: Creates new Policy with offending Statements removed                                                                                                                                                                                      |
| IAM User No Policies Check                 | Checks that none of your IAM users have policies attached. IAM users must inherit permissions from IAM groups or roles.                                                                                                                         | Detaches Managed Policies from offending IAM User                                                                                                                                                                                                   |
| IAM User Unused Credentials Check          | Checks whether AWS Identity and Access Management (IAM) users have passwords or active access keys that have not been used within 90 days.                                                                                                      | :warning: Deletes Access Key / Login Profile                                                                                                                                                                                                        |
| MFA Enabled for IAM Console Access         | Checks whether AWS Multi-Factor Authentication (MFA) is enabled for all AWS Identity and Access Management (IAM) users that use a console password.                                                                                             | :warning: Deletes user's Login Profile only. [Deleting a user's password does not prevent a user from accessing AWS through the command line interface or the API.](https://docs.aws.amazon.com/cli/latest/reference/iam/delete-login-profile.html) |

#### Storage

| Rule                              | Description                                            | Remediation                                                                                                 |
| --------------------------------- | ------------------------------------------------------ | ----------------------------------------------------------------------------------------------------------- |
| S3 Bucket Logging Enabled         | Checks whether logging is enabled for your S3 buckets. | Creates new S3 Bucket `<Account Number>-<Region>-access-logs` for logging with a prefix of `<Bucket Name>/` |
| S3 Bucket Public Read Prohibited  | Checks to see if S3 buckets are publicly readable.     | :warning: Sets S3 Bucket ACL to `private`                                                                   |
| S3 Bucket Public Write Prohibited | Checks to see if S3 buckets allow public write.        | :warning: Sets S3 Bucket ACL to `private`                                                                   |

## Resources

The table below details all AWS resources created when deploying the application.

| Service               | Resource ID                                                                                          |
| --------------------- | ---------------------------------------------------------------------------------------------------- |
| CloudFormation Stack  | `auto-remediate`                                                                                     |
| CloudWatch Event Rule | `auto-remediate-config-compliance`                                                                   |
| DynamoDB Table        | `auto-remediate-settings`                                                                            |
| Lambda Function       | `auto-remediate`                                                                                     |
|                       | `auto-remediate-dlq`                                                                                 |
|                       | `auto-remediate-setup`                                                                               |
| SNS Topic             | `auto-remediate-log` (not functional [#19](https://github.com/servian/aws-auto-remediate/issues/19)) |
|                       | `auto-remediate-missing-remediation`                                                                 |
| SQS Queue             | `auto-remediate-config-compliance`                                                                   |
|                       | `auto-remediate-dlq`                                                                                 |

## Coverage

[Full list of development and automated testing coverage found here.](COVERAGE.md)
